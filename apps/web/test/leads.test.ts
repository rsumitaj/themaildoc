import { describe, expect, it } from 'vitest';
import { HELP_OPTIONS, validateLead } from '../src/lib/leads';

const valid = {
  name: '  Sam Patel ',
  email: 'Sam@Example.COM',
  helpWith: 'dmarc',
};

describe('validateLead', () => {
  it('accepts the minimum a person can reasonably give', () => {
    const result = validateLead(valid);
    expect(result.ok).toBe(true);
    if (!result.ok) return;

    expect(result.lead.name).toBe('Sam Patel');
    expect(result.lead.email).toBe('sam@example.com');
    expect(result.lead.helpWith).toBe('dmarc');
    expect(result.lead.company).toBeNull();
    expect(result.lead.domain).toBeNull();
  });

  it('normalises the domain the same way the checkup does', () => {
    const result = validateLead({ ...valid, domain: 'https://WWW.Example.co.uk/path' });
    expect(result.ok && result.lead.domain).toBe('www.example.co.uk');
  });

  it('drops a domain that is not one rather than storing rubbish', () => {
    expect(validateLead({ ...valid, domain: 'not a domain' })).toMatchObject({
      ok: true,
      lead: { domain: null },
    });
  });

  it('keeps the clinical context when it is real', () => {
    const result = validateLead({
      ...valid,
      vitalsScore: 32,
      vitalsBand: 'critical',
      spoofable: 'SPOOFABLE',
      sourcePage: '/lab/spf-checker',
    });

    expect(result.ok && result.lead).toMatchObject({
      vitalsScore: 32,
      vitalsBand: 'CRITICAL',
      spoofable: 'SPOOFABLE',
      sourcePage: '/lab/spf-checker',
    });
  });

  it('refuses invented context rather than storing it', () => {
    const result = validateLead({
      ...valid,
      vitalsScore: 9000,
      vitalsBand: 'PERFECT',
      spoofable: 'MAYBE',
    });

    expect(result.ok && result.lead).toMatchObject({
      vitalsScore: null,
      vitalsBand: null,
      spoofable: null,
    });
  });

  it('asks for a name and an address', () => {
    expect(validateLead({ ...valid, name: '   ' })).toMatchObject({ ok: false, field: 'name' });
    expect(validateLead({ ...valid, email: '' })).toMatchObject({ ok: false, field: 'email' });
  });

  it.each(['sam', 'sam@example', 'sam @example.com', 'a@b@c.com'])(
    'rejects %s as an address',
    (email) => {
      expect(validateLead({ ...valid, email })).toMatchObject({ ok: false, field: 'email' });
    },
  );

  it('accepts the addresses people really have', () => {
    for (const email of [
      'sam+dmarc@example.co.uk',
      'first.last@mail.example.com',
      "o'brien@example.ie",
    ]) {
      expect(validateLead({ ...valid, email }).ok, email).toBe(true);
    }
  });

  it('requires a reason we recognise', () => {
    expect(validateLead({ ...valid, helpWith: '' })).toMatchObject({ ok: false, field: 'helpWith' });
    expect(validateLead({ ...valid, helpWith: 'spf' })).toMatchObject({
      ok: false,
      field: 'helpWith',
    });
    expect(validateLead({ ...valid, helpWith: 'DROP TABLE leads' })).toMatchObject({
      ok: false,
      field: 'helpWith',
    });
    for (const option of HELP_OPTIONS) {
      expect(validateLead({ ...valid, helpWith: option.value }).ok, option.value).toBe(true);
    }
  });

  it('silently fails a submission that filled the honeypot', () => {
    const result = validateLead({ ...valid, website: 'http://spam.example' });
    // Same wording as an unreadable body: a bot should learn nothing.
    expect(result).toMatchObject({ ok: false, field: 'form' });
  });

  it('caps what it will store instead of truncating in the database', () => {
    const long = 'x'.repeat(5_000);
    expect(validateLead({ ...valid, message: long })).toMatchObject({ ok: false, field: 'message' });
    expect(validateLead({ ...valid, company: long })).toMatchObject({
      ok: true,
      lead: { company: 'x'.repeat(160) },
    });
  });

  it('refuses anything that is not an object', () => {
    expect(validateLead(null)).toMatchObject({ ok: false });
    expect(validateLead('name=sam')).toMatchObject({ ok: false });
  });
});
