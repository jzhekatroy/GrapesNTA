(function (global) {
  let writePermissions = null;

  function setEffectiveWritePermissions(perms) {
    writePermissions = perms || null;
  }

  function canWritePage(pageId) {
    if (!writePermissions) return true;
    return !!writePermissions[pageId];
  }

  global.AuthAccess = {
    setEffectiveWritePermissions,
    canWritePage,
  };
})(window);
