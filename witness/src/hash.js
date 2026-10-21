import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex } from '@noble/hashes/utils.js';

export const digest = bytes => 'sha256:' + bytesToHex(sha256(bytes));
export const rawHash = bytes => sha256(bytes);
export const hex = bytesToHex;

// A descriptor exists so a reviewer knows what to ask the custodian for. It is
// a category, not a reference: "plan of care", "discharge summary".
//
// The format forbids it containing a path, a URL, a record locator, or anything
// that identifies a person. Nothing enforced that until now, and an unvalidated
// free text field inside a record that is otherwise free of narrative is exactly
// where protected information ends up. It arrives by convenience, somebody
// passes the filename they already had in a variable, and it is then signed,
// chained and permanent.
//
// Letters, digits, spaces and hyphens, with no run of four or more digits.
//
// Digits have to be allowed because several legitimate document kinds are named
// after a standard: "837I claim", "835 remittance". Those are categories, not
// references. What a long digit run means, in practice, is a record number, a
// medical record number, a date or an account: "DOC-77213", "MRN-55210". Three
// digits names a standard. Five digits names a patient's chart.
//
// Everything else is refused by construction rather than by trying to detect it:
// no slashes, no dots, no colons, no at signs, so no paths, no URLs, no email,
// no filenames.
const DESCRIPTOR = /^[a-z0-9][a-z0-9 \-]{2,63}$/i;
const LONG_DIGIT_RUN = /\d{4,}/;

// The pattern above refuses paths, URLs, locators and record numbers, and it
// cannot refuse a name. "patient Jane Doe" and "plan of care" are structurally
// identical and no regular expression will ever tell them apart.
//
// So the pattern is the second line of defence and this is the first. The set
// of document kinds a frozen format with six record types can legitimately
// point at is small and knowable. An allowlist states it, and anything outside
// it is refused rather than inspected.
//
// Adding an entry is a deliberate act. It should name a category of document
// that a reviewer could ask a custodian for, and nothing narrower.
export const DESCRIPTORS = new Set([
  'discharge summary',
  'consent form',
  'plan of care',
  'physician certification',
  'visit documentation',
  'authenticated clinical document',
  'face to face encounter note',
  'progress note',
  'history and physical',
  'operative report',
  'imaging report',
  'laboratory report',
  'medication administration record',
  'order',
  '837I claim',
  '837P claim',
  '835 remittance'
]);

export function assertDescriptor(descriptor) {
  if (typeof descriptor !== 'string') {
    throw new Error('an evidence descriptor is required');
  }
  if (!DESCRIPTOR.test(descriptor) || LONG_DIGIT_RUN.test(descriptor)) {
    throw new Error(
      `descriptor ${JSON.stringify(descriptor)} is malformed. ` +
      'It must be 3 to 64 characters of letters, digits, spaces and hyphens with no run of ' +
      'four or more digits. No paths, locators, record numbers or names.'
    );
  }
  if (!DESCRIPTORS.has(descriptor)) {
    throw new Error(
      `descriptor ${JSON.stringify(descriptor)} is not in the permitted set. ` +
      'A descriptor names a kind of document a reviewer could ask a custodian for, ' +
      'never a particular one. Adding a new kind is a deliberate change to DESCRIPTORS.'
    );
  }
  return descriptor;
}

// Fingerprint a source document. The document itself never leaves its system.
export function fingerprint(documentBytes, descriptor) {
  return { alg: 'sha256', digest: digest(documentBytes), descriptor: assertDescriptor(descriptor) };
}
