const toString = Object.prototype.toString;

/**
 * Returns true if any argument is null, undefined, or an empty/whitespace string
 * @param ...obj values to check
 * @return {Boolean} whether any value is empty
 */
export function isEmpty() {
  for (let obj of arguments) {
    if (obj === null || obj === undefined) {
      return true;
    } else if (isType('String', obj) && obj.trim() === '') {
      return true;
    }
  }
  return false;
}

export const isType = (type, content) => toString.call(content) === `[object ${type}]`;
