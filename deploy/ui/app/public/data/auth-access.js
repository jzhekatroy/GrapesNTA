(function (global) {
  let writePermissions = null;
  let grantedActions = null;

  function setEffectiveWritePermissions(perms) {
    writePermissions = perms || null;
  }

  function setGrantedActions(actions) {
    grantedActions = Array.isArray(actions) ? actions : null;
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
    setEffectiveWritePermissions,
    setGrantedActions,
    canWritePage,
    can,
  };
})(window);
