import { render } from "@testing-library/react";
import { SourceTag } from "../components/common";

describe("SourceTag", () => {
  it("renders a rule pill for source rule", () => {
    const { container } = render(<SourceTag source="rule" />);
    const el = container.querySelector(".source-tag")!;
    expect(el).toHaveTextContent("rule");
    expect(el).toHaveClass("pill");
  });
  it.each([["ml" as const], [undefined]])("renders nothing for %s", (s) => {
    const { container } = render(<SourceTag source={s} />);
    expect(container).toBeEmptyDOMElement();
  });
});
