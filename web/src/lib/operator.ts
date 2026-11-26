// The single operator behind a no-login deployment. There is nobody to identify:
// the backend trusts whoever reaches it over loopback (server/auth_mode.go), so the
// UI shows a fixed identity instead of decoding a JWT that no longer exists.
export interface Operator {
  id: string;
  name: string;
  username: string;
  email: string;
  avatar: string;
  role: string;
}

export const OPERATOR: Operator = {
  id: "local",
  name: "Operator",
  username: "operator",
  email: "local session",
  avatar: "",
  role: "owner",
};
