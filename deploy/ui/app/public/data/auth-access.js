(function (global) {
  let readPermissions = null;
  let writePermissions = null;
  let grantedActions = null;

  function setEffectivePermissions(perms) {
    readPermissions = perms || null;
  }

  function setEffectiveWritePermissions(perms) {
    writePermissions = perms || null;
  }

  function setGrantedActions(actions) {
    grantedActions = Array.isArray(actions) ? actions : null;
  }

  function canAccessPage(pageId) {
    if (!readPermissions) return true;
    return !!readPermissions[pageId];
  }

  function canWritePage(pageId) {
    if (!writePermissions) return true;
    return !!writePermissions[pageId];
  }

  function can(action) {
    if (!grantedActions) return true;
    return grantedActions.includes(action);
  }

  global.AuthAccess = {
    setEffectivePermissions,
    setEffectiveWritePermissions,
    setGrantedActions,
    canAccessPage,
    canWritePage,
    can,
  };
})(window);
