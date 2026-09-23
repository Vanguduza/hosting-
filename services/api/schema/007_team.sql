-- One-time, bounded capability invitations for OIDC subjects. The token is
-- returned once; only its SHA-256 digest is stored in the control database.
CREATE TABLE hosting.team_invitations (
  id uuid PRIMARY KEY,
  organization_id uuid NOT NULL REFERENCES hosting.organizations(id),
  token_hash bytea NOT NULL UNIQUE CHECK (length(token_hash)=32),
  idempotency_key uuid NOT NULL,
  role text NOT NULL CHECK (role IN ('admin','viewer')),
  duration_hours integer NOT NULL CHECK (duration_hours BETWEEN 1 AND 72),
  issued_by text NOT NULL,
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  accepted_by text,
  accepted_at timestamptz,
  revoked_at timestamptz,
  CHECK (expires_at > created_at AND expires_at <= created_at + interval '72 hours'),
  CHECK ((accepted_by IS NULL) = (accepted_at IS NULL)),
  CHECK (accepted_at IS NULL OR revoked_at IS NULL),
  UNIQUE (organization_id,idempotency_key)
);
CREATE INDEX team_invitations_org_idx ON hosting.team_invitations(organization_id,created_at DESC);
GRANT SELECT,INSERT,UPDATE (revoked_at) ON hosting.team_invitations TO hosting_api;
ALTER TABLE hosting.team_invitations ENABLE ROW LEVEL SECURITY;
ALTER TABLE hosting.team_invitations FORCE ROW LEVEL SECURITY;
CREATE POLICY team_owner_select ON hosting.team_invitations FOR SELECT TO hosting_api
  USING (EXISTS (SELECT 1 FROM hosting.memberships m WHERE m.organization_id=team_invitations.organization_id
                AND m.actor_sub=current_setting('hosting.actor_sub',true) AND m.role='owner'));
CREATE POLICY team_owner_insert ON hosting.team_invitations FOR INSERT TO hosting_api
  WITH CHECK (issued_by=current_setting('hosting.actor_sub',true) AND
              EXISTS (SELECT 1 FROM hosting.memberships m WHERE m.organization_id=team_invitations.organization_id
                      AND m.actor_sub=current_setting('hosting.actor_sub',true) AND m.role='owner'));
CREATE POLICY team_owner_update ON hosting.team_invitations FOR UPDATE TO hosting_api
  USING (accepted_at IS NULL AND revoked_at IS NULL AND
         EXISTS (SELECT 1 FROM hosting.memberships m WHERE m.organization_id=team_invitations.organization_id
                 AND m.actor_sub=current_setting('hosting.actor_sub',true) AND m.role='owner'))
  WITH CHECK (revoked_at IS NOT NULL);

-- The membership table deliberately exposes only self under RLS. These fixed
-- functions make owner roster/removal and one-time acceptance possible without
-- granting the API role cross-tenant SELECT or direct membership INSERT/DELETE.
CREATE FUNCTION hosting.team_members(p_org uuid)
RETURNS TABLE(actor_sub text, role text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM hosting.memberships m WHERE m.organization_id=p_org
                 AND m.actor_sub=current_setting('hosting.actor_sub',true) AND m.role='owner') THEN
    RETURN;
  END IF;
  RETURN QUERY SELECT m.actor_sub,m.role FROM hosting.memberships m
    WHERE m.organization_id=p_org ORDER BY m.actor_sub;
END $$;

CREATE FUNCTION hosting.accept_team_invitation(p_hash bytea)
RETURNS TABLE(invitation_id uuid, organization_id uuid, assigned_role text, replayed boolean)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE
  invite hosting.team_invitations%ROWTYPE;
  actor text := current_setting('hosting.actor_sub',true);
BEGIN
  IF actor IS NULL OR length(actor) NOT BETWEEN 1 AND 255 OR length(p_hash) <> 32 THEN
    RETURN;
  END IF;
  SELECT * INTO invite FROM hosting.team_invitations t WHERE t.token_hash=p_hash FOR UPDATE;
  IF NOT FOUND OR invite.revoked_at IS NOT NULL OR invite.expires_at<=now() THEN
    RETURN;
  END IF;
  IF invite.accepted_by IS NOT NULL THEN
    IF invite.accepted_by=actor AND EXISTS
       (SELECT 1 FROM hosting.memberships m WHERE m.organization_id=invite.organization_id
        AND m.actor_sub=actor AND m.role=invite.role) THEN
      RETURN QUERY SELECT invite.id,invite.organization_id,invite.role,true;
    END IF;
    RETURN;
  END IF;
  PERFORM 1 FROM hosting.organizations o WHERE o.id=invite.organization_id FOR UPDATE;
  IF EXISTS (SELECT 1 FROM hosting.memberships m WHERE m.organization_id=invite.organization_id
             AND m.actor_sub=actor) THEN
    RETURN;
  END IF;
  INSERT INTO hosting.memberships(organization_id,actor_sub,role)
    VALUES (invite.organization_id,actor,invite.role);
  UPDATE hosting.team_invitations t SET accepted_by=actor,accepted_at=now() WHERE t.id=invite.id;
  RETURN QUERY SELECT invite.id,invite.organization_id,invite.role,false;
END $$;

CREATE FUNCTION hosting.remove_team_member(p_org uuid,p_target text)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE
  actor text := current_setting('hosting.actor_sub',true);
  target_role text;
BEGIN
  PERFORM 1 FROM hosting.organizations o WHERE o.id=p_org FOR UPDATE;
  IF actor IS NULL OR actor=p_target OR NOT EXISTS
     (SELECT 1 FROM hosting.memberships m WHERE m.organization_id=p_org AND m.actor_sub=actor AND m.role='owner') THEN
    RETURN false;
  END IF;
  SELECT m.role INTO target_role FROM hosting.memberships m
    WHERE m.organization_id=p_org AND m.actor_sub=p_target FOR UPDATE;
  IF target_role IS NULL OR target_role='owner' THEN
    RETURN false;
  END IF;
  DELETE FROM hosting.memberships m WHERE m.organization_id=p_org AND m.actor_sub=p_target;
  RETURN true;
END $$;

REVOKE ALL ON FUNCTION hosting.team_members(uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION hosting.accept_team_invitation(bytea) FROM PUBLIC;
REVOKE ALL ON FUNCTION hosting.remove_team_member(uuid,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION hosting.team_members(uuid),hosting.accept_team_invitation(bytea),
  hosting.remove_team_member(uuid,text) TO hosting_api;
