(function (global) {
  let readPermissions = null;
  let writePermissions = null;

  function setEffectivePermissions(perms) {
    readPermissions = perms || null;
  }

  function setEffectiveWritePermissions(perms) {
    writePermissions = perms || null;
  }

  function canAccessPage(pageId) {
    if (!readPermissions) return true;
    return !!readPermissions[pageId];
  }

  function canWritePage(pageId) {
    if (!writePermissions) return true;
    return !!writePermissions[pageId];
  }

  global.AuthAccess = {
    setEffectivePermissions,
    setEffectiveWritePermissions,
    canAccessPage,
    canWritePage,
  };
})(window);
