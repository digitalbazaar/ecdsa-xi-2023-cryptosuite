//FIXME: where should these helper functions live? probably bad code duplication
export function concat(b1, b2)
{
    const rval = new Uint8Array(b1.length + b2.length);
    rval.set(b1, 0);
    rval.set(b2, b1.length);
    return rval;
}