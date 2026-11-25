import { oneLine } from "../format";

describe("oneLine", () => {
  it("collapses whitespace runs, line breaks and tabs to single spaces and trims", () => {
    expect(oneLine("  a \n\n b\t\tc \r\n ")).toBe("a b c");
  });
  it("turns control characters into spaces", () => {
    expect(oneLine("a\u0000b\u001fc\u007fd")).toBe("a b c d");
  });
  it.each(["‪", "‫", "‬", "‭", "‮", "⁦", "⁧", "⁨", "⁩", "‎", "‏"])(
    "replaces bidi mark %j", (ch) => { expect(oneLine(`a${ch}b`)).toBe("a b"); });
  it("leaves ordinary text and unicode letters alone", () => { expect(oneLine("héllo wörld ✓")).toBe("héllo wörld ✓"); });
  it("empty and blank give an empty string", () => { expect(oneLine("")).toBe(""); expect(oneLine(" \n\t ")).toBe(""); });
  it("caps at max with an ellipsis, 200 by default", () => {
    expect(oneLine("x".repeat(200))).toBe("x".repeat(200));
    const long = oneLine("x".repeat(201));
    expect(long).toHaveLength(200);
    expect(long.endsWith("…")).toBe(true);
  });
  it("respects a custom max and applies it after flattening", () => {
    expect(oneLine("abcdefghij", 5)).toBe("abcd…");
    expect(oneLine("ab\n\n\ncd", 5)).toBe("ab cd");
    expect(oneLine("abc", 3)).toBe("abc");
  });
  it("a trailing space before the cut is not left dangling beyond max", () => {
    expect(oneLine("a b c d e f", 6).length).toBeLessThanOrEqual(6);
  });
});

describe("oneLine unicode classes", () => {
  it.each([
    ["NEL", "\u0085"], ["C1 control", "\u0090"], ["Arabic letter mark", "؜"], ["zero-width space", "​"],
    ["ZWNJ", "‌"], ["ZWJ", "‍"], ["word joiner", "⁠"], ["invisible times", "⁢"], ["invisible plus", "⁤"],
    ["soft hyphen", "­"], ["BOM", "﻿"], ["private use", ""], ["private use end", ""],
    ["line separator", " "], ["paragraph separator", " "], ["no-break space", " "],
  ])("%s becomes a space", (_n, ch) => { expect(oneLine(`a${ch}b`)).toBe("a b"); });
  it("a mix collapses to one space", () => { expect(oneLine("a​‌\u0085  b")).toBe("a b"); });
  it("only such characters give an empty string", () => { expect(oneLine("​\u0085")).toBe(""); });
  it("counts code points: an emoji at the cut is never split", () => {
    const out = oneLine("ab😀😀😀", 4);
    expect(out).toBe("ab😀…");
    expect([...out]).toHaveLength(4);
    expect(out).not.toMatch(/[\ud800-\udbff](?![\udc00-\udfff])/);
  });
  it("an emoji string within the limit is untouched", () => { expect(oneLine("😀😀😀", 3)).toBe("😀😀😀"); });
  it("surrogate pairs count as one against the default cap", () => {
    expect([...oneLine("😀".repeat(250))]).toHaveLength(200);
    expect(oneLine("😀".repeat(200))).toBe("😀".repeat(200));
  });
});
