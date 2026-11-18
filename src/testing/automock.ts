/**
 * ESM stand-in for `jest.mock('<pkg>')` automocking: jest cannot automock an ESM-only package,
 * so tests import the real namespace and swap every function (and method of a plain object,
 * such as `core.summary`) for a `jest.fn()`. Register the result with
 * `jest.unstable_mockModule(name, () => mock)` BEFORE importing the module under test.
 */
import { jest } from '@jest/globals';

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Loose = any;

export function automock<T extends object>(actual: T): T {
  const out: Loose = {};
  for (const [key, value] of Object.entries(actual)) {
    if (typeof value === 'function') out[key] = jest.fn();
    else if (value !== null && typeof value === 'object') {
      const proto = Object.getPrototypeOf(value);
      out[key] = proto === Object.prototype || proto === null ? automock(value) : automockInstance(value);
    } else out[key] = value;
  }
  return out;
}

/** A class instance (`core.summary` is one): its methods become mocks that return the instance. */
function automockInstance(instance: object): object {
  const out: Loose = {};
  const proto = Object.getPrototypeOf(instance);
  for (const key of [...Object.getOwnPropertyNames(proto), ...Object.keys(instance)]) {
    if (key === 'constructor') continue;
    const value = (instance as Loose)[key];
    if (typeof value === 'function') out[key] = jest.fn(() => out);
  }
  return out;
}
