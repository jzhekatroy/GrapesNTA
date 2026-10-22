'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { observationToRow } = require('./observations-store');
const {
  GENERAL_SECTION_ID,
  ADMIN_ROLE_ID,
  resolveObservationSectionId,
  buildSectionAccess,
  canViewInSection,
  canEditInSection,
  canTransferSection,
} = require('./observation-sections');

describe('observation section access', () => {
  const sections = ['general', 'support', 'sales'];
  const rolesBySection = {
    general: { Operator: 'edit', ReadOnly: 'view' },
    support: { Operator: 'edit' },
    sales: { ReadOnly: 'view' },
  };

  it('maps missing map entry to general', () => {
    assert.equal(resolveObservationSectionId(null, new Set()), GENERAL_SECTION_ID);
    assert.equal(resolveObservationSectionId('support', new Set(['support'])), GENERAL_SECTION_ID);
    assert.equal(resolveObservationSectionId('support', new Set()), 'support');
  });

  it('Administrator gets edit on all sections', () => {
    const access = buildSectionAccess({
      roleId: ADMIN_ROLE_ID,
      hasObservationsAccess: true,
      activeSectionIds: sections,
      rolesBySection,
    });
    assert.equal(access.general, 'edit');
    assert.equal(access.support, 'edit');
    assert.equal(access.sales, 'edit');
  });

  it('no observations permission yields empty access', () => {
    const access = buildSectionAccess({
      roleId: 'Operator',
      hasObservationsAccess: false,
      activeSectionIds: sections,
      rolesBySection,
    });
    assert.deepEqual(access, {});
  });

  it('Operator: view in general allows read not edit; edit in support', () => {
    const access = buildSectionAccess({
      roleId: 'Operator',
      hasObservationsAccess: true,
      activeSectionIds: sections,
      rolesBySection,
    });
    assert.equal(canViewInSection(access, 'general'), true);
    assert.equal(canEditInSection(access, 'general'), true);
    assert.equal(canViewInSection(access, 'sales'), false);
    assert.equal(canEditInSection(access, 'sales'), false);
  });

  it('ReadOnly: view in sales, no edit', () => {
    const access = buildSectionAccess({
      roleId: 'ReadOnly',
      hasObservationsAccess: true,
      activeSectionIds: sections,
      rolesBySection,
    });
    assert.equal(canViewInSection(access, 'sales'), true);
    assert.equal(canEditInSection(access, 'sales'), false);
    assert.equal(canViewInSection(access, 'support'), false);
  });

  it('transfer requires edit in both sections', () => {
    const access = buildSectionAccess({
      roleId: 'Operator',
      hasObservationsAccess: true,
      activeSectionIds: sections,
      rolesBySection,
    });
    assert.equal(canTransferSection(access, 'general', 'support'), true);
    assert.equal(canTransferSection(access, 'general', 'sales'), false);
  });
});

describe('observation store and worker isolation', () => {
  it('observationToRow does not include section fields', () => {
    const row = observationToRow({
      id: 'obs-1',
      ownerId: 'u1',
      isShared: true,
      name: 'Test',
      folder: 'f',
      lookback: '1h',
      widgets: [],
      live: {},
      materialize: {},
      report: {},
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    });
    assert.equal('section_id' in row, false);
    assert.equal('sectionId' in row, false);
  });
});
