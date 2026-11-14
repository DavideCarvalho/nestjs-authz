---
"@dudousxd/nestjs-authz": minor
---

`authorizeByRoles({ roles, loginPath })` and `authorizeByPermission(permission, { loginPath })` send a guest to the app's sign-in page instead of the console's bare 401. A page load is redirected to `loginPath?redirect=<page>`, and a console API call answers 401 with that `redirectTo`, which the console follows. A signed-in user without access still gets 403. Set `redirectParam` to rename the `redirect` parameter.
