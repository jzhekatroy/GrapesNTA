'use strict';

(function explorerFilterTreeModule() {
  const EXPLORER_FILTER_MAX_GROUP_DEPTH = 3;
  const EXPLORER_FILTER_LOGIC = new Set(['and', 'or', 'and_not', 'or_not']);

  function normalizeFilterLogicValue(logic) {
    const key = String(logic || 'and').trim().toLowerCase();
    return EXPLORER_FILTER_LOGIC.has(key) ? key : 'and';
  }

  function isExplorerFilterGroup(node) {
    return node?.type === 'group' && Array.isArray(node.children);
  }

  function isExplorerFilterLeaf(node) {
    return node != null && !isExplorerFilterGroup(node);
  }

  function newExplorerFilterId() {
    return `f-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
  }

  function newExplorerFilterGroup(partial = {}) {
    return {
      type: 'group',
      id: partial.id || newExplorerFilterId(),
      logic: normalizeFilterLogicValue(partial.logic),
      children: Array.isArray(partial.children) ? partial.children : [],
    };
  }

  function walkExplorerFilters(filters, visitor, { parent = null, depth = 0 } = {}) {
    if (typeof visitor !== 'function') return;
    (Array.isArray(filters) ? filters : []).forEach((node, index) => {
      visitor(node, { parent, index, depth });
      if (isExplorerFilterGroup(node)) {
        walkExplorerFilters(node.children, visitor, { parent: node, depth: depth + 1 });
      }
    });
  }

  function flattenExplorerFilters(filters) {
    const out = [];
    walkExplorerFilters(filters, (node) => {
      if (isExplorerFilterLeaf(node)) out.push(node);
    });
    return out;
  }

  function explorerFilterDepth(filters, nodeId) {
    let depth = null;
    walkExplorerFilters(filters, (node, ctx) => {
      if (node.id === nodeId) depth = ctx.depth;
    });
    return depth;
  }

  function explorerFilterGroupDepth(node) {
    if (!isExplorerFilterGroup(node)) return 0;
    let max = 0;
    (node.children || []).forEach((child) => {
      if (isExplorerFilterGroup(child)) {
        max = Math.max(max, 1 + explorerFilterGroupDepth(child));
      }
    });
    return max;
  }

  function cloneExplorerFilterNode(node, idFactory = newExplorerFilterId) {
    if (isExplorerFilterGroup(node)) {
      return {
        type: 'group',
        id: node.id ?? idFactory(),
        logic: normalizeFilterLogicValue(node.logic),
        children: (node.children || []).map((child) => cloneExplorerFilterNode(child, idFactory)),
      };
    }
    return {
      ...node,
      id: node.id ?? idFactory(),
      logic: normalizeFilterLogicValue(node.logic),
    };
  }

  function cloneExplorerFilterTree(filters, idFactory = newExplorerFilterId) {
    return (Array.isArray(filters) ? filters : []).map((node) => cloneExplorerFilterNode(node, idFactory));
  }

  function normalizeExplorerFilterNode(node, { preserveId = true } = {}) {
    if (isExplorerFilterGroup(node)) {
      const children = (Array.isArray(node.children) ? node.children : [])
        .map((child) => normalizeExplorerFilterNode(child, { preserveId }))
        .filter(Boolean);
      if (!children.length) return null;
      return {
        type: 'group',
        ...(preserveId && node.id != null ? { id: node.id } : {}),
        logic: normalizeFilterLogicValue(node.logic),
        children,
      };
    }
    const field = String(node?.field || node?.dim || '').trim();
    if (!field) return null;
    let op = String(node?.op || '=').trim().toLowerCase();
    if (field === 'tcp_flags') {
      if (!node?.op || op === '=') op = 'eq';
      if (op === '!=') op = 'neq';
    }
    return {
      ...(preserveId && node?.id != null ? { id: node.id } : {}),
      field,
      op,
      value: node?.value ?? '',
      label: node?.label ?? null,
      logic: normalizeFilterLogicValue(node?.logic),
    };
  }

  function normalizeExplorerFilterTree(filters, options = {}) {
    return (Array.isArray(filters) ? filters : [])
      .map((node) => normalizeExplorerFilterNode(node, options))
      .filter(Boolean);
  }

  function findExplorerFilterLocation(filters, nodeId, parent = null) {
    const list = Array.isArray(filters) ? filters : [];
    for (let index = 0; index < list.length; index += 1) {
      const node = list[index];
      if (node?.id === nodeId) {
        return { node, parent, index, siblings: list };
      }
      if (isExplorerFilterGroup(node)) {
        const nested = findExplorerFilterLocation(node.children, nodeId, node);
        if (nested) return nested;
      }
    }
    return null;
  }

  function detachExplorerFilterNode(filters, nodeId) {
    const loc = findExplorerFilterLocation(filters, nodeId);
    if (!loc) return { next: filters, removed: null };
    const removed = loc.siblings.splice(loc.index, 1)[0] || null;
    return { next: [...filters], removed };
  }

  function insertExplorerFilterNode(filters, parentId, index, node) {
    const next = cloneExplorerFilterTree(filters);
    if (parentId == null) {
      const safeIndex = Math.max(0, Math.min(index, next.length));
      next.splice(safeIndex, 0, node);
      return next;
    }
    const parentLoc = findExplorerFilterLocation(next, parentId);
    if (!parentLoc || !isExplorerFilterGroup(parentLoc.node)) return next;
    const children = [...(parentLoc.node.children || [])];
    const safeIndex = Math.max(0, Math.min(index, children.length));
    children.splice(safeIndex, 0, node);
    parentLoc.node.children = children;
    return next;
  }

  function moveExplorerFilterNode(filters, dragId, targetParentId, targetIndex) {
    if (dragId == null) return filters;
    const { next, removed } = detachExplorerFilterNode(filters, dragId);
    if (!removed) return filters;

    if (isExplorerFilterGroup(removed)) {
      const subtreeDepth = 1 + explorerFilterGroupDepth(removed);
      const targetDepth = targetParentId == null
        ? 0
        : (explorerFilterDepth(next, targetParentId) ?? 0) + 1;
      if (targetDepth + subtreeDepth > EXPLORER_FILTER_MAX_GROUP_DEPTH) {
        return filters;
      }
    }

    if (targetParentId === dragId) return filters;
    if (targetParentId != null) {
      let blocked = false;
      walkExplorerFilters([removed], (node) => {
        if (node.id === targetParentId) blocked = true;
      });
      if (blocked) return filters;
    }

    return insertExplorerFilterNode(next, targetParentId, targetIndex, removed);
  }

  function reorderExplorerList(items, fromIndex, toIndex) {
    const list = [...(Array.isArray(items) ? items : [])];
    if (fromIndex < 0 || fromIndex >= list.length) return list;
    if (toIndex < 0 || toIndex > list.length) return list;
    if (fromIndex === toIndex) return list;
    const [item] = list.splice(fromIndex, 1);
    const insertAt = Math.min(Math.max(toIndex, 0), list.length);
    if (insertAt === fromIndex) return items;
    list.splice(insertAt, 0, item);
    return list;
  }

  function updateExplorerFilterNode(filters, nodeId, patch) {
    const next = cloneExplorerFilterTree(filters);
    const loc = findExplorerFilterLocation(next, nodeId);
    if (!loc?.node) return next;
    Object.assign(loc.node, patch);
    if (isExplorerFilterGroup(loc.node) && !Array.isArray(loc.node.children)) {
      loc.node.children = [];
    }
    return next;
  }

  function removeExplorerFilterNode(filters, nodeId) {
    const { next } = detachExplorerFilterNode(filters, nodeId);
    return next;
  }

  function addExplorerFilterGroup(filters, { parentId = null, index = null, logic = 'and' } = {}) {
    const group = newExplorerFilterGroup({ logic });
    const targetIndex = index == null
      ? (parentId == null ? filters.length : (findExplorerFilterLocation(filters, parentId)?.node?.children?.length || 0))
      : index;
    const parentDepth = parentId == null ? -1 : explorerFilterDepth(filters, parentId);
    if (parentDepth + 1 >= EXPLORER_FILTER_MAX_GROUP_DEPTH) return filters;
    return insertExplorerFilterNode(filters, parentId, targetIndex, group);
  }

  function countExplorerFilterLeaves(filters) {
    return flattenExplorerFilters(filters).length;
  }

  function explorerFilterUsesField(filters, fieldId) {
    const needle = String(fieldId || '').trim();
    if (!needle) return false;
    let found = false;
    walkExplorerFilters(filters, (node) => {
      if (isExplorerFilterLeaf(node) && String(node.field || '').trim() === needle) found = true;
    });
    return found;
  }

  function pruneExplorerFilterTree(filters, keepLeaf) {
    const predicate = typeof keepLeaf === 'function' ? keepLeaf : () => true;
    return (Array.isArray(filters) ? filters : []).map((node) => {
      if (isExplorerFilterGroup(node)) {
        const children = pruneExplorerFilterTree(node.children, predicate);
        if (!children.length) return null;
        return { ...node, children };
      }
      return predicate(node) ? node : null;
    }).filter(Boolean);
  }

  const api = {
    EXPLORER_FILTER_MAX_GROUP_DEPTH,
    EXPLORER_FILTER_LOGIC,
    isExplorerFilterGroup,
    isExplorerFilterLeaf,
    newExplorerFilterId,
    newExplorerFilterGroup,
    walkExplorerFilters,
    flattenExplorerFilters,
    explorerFilterDepth,
    explorerFilterGroupDepth,
    cloneExplorerFilterNode,
    cloneExplorerFilterTree,
    normalizeExplorerFilterNode,
    normalizeExplorerFilterTree,
    findExplorerFilterLocation,
    detachExplorerFilterNode,
    insertExplorerFilterNode,
    moveExplorerFilterNode,
    reorderExplorerList,
    updateExplorerFilterNode,
    removeExplorerFilterNode,
    addExplorerFilterGroup,
    countExplorerFilterLeaves,
    explorerFilterUsesField,
    normalizeFilterLogicValue,
    pruneExplorerFilterTree,
  };

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = api;
  }

  if (typeof window !== 'undefined') {
    window.ExplorerFilterTree = api;
  }
}());
