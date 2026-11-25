import { render, screen } from "@testing-library/react";
import ExplanationChart from "../components/ExplanationChart";
import { endpoint, percent, protocolName } from "../format";
import { query } from "../api/client";

describe("ExplanationChart", () => {
  it("shows each feature with its signed contribution", () => {
    render(
      <ExplanationChart
        explanation={{
          method: "shap",
          predicted_class: "PortScan",
          output_space: "log_odds",
          top_features: [
            { feature: "syn_count", value: 40, contribution: 1.2 },
            { feature: "bwd_bytes", value: 0, contribution: -0.3 },
          ],
        }}
      />,
    );
    expect(screen.getByText(/syn_count/)).toBeInTheDocument();
    expect(screen.getByText("+1.200")).toBeInTheDocument();
    expect(screen.getByText("-0.300")).toBeInTheDocument();
  });

  it("renders attacker-controlled text as text, never as HTML", () => {
    const evil = '<img src=x onerror="alert(1)">';
    const { container } = render(
      <ExplanationChart explanation={{ predicted_class: evil, top_features: [{ feature: evil, value: 1, contribution: 1 }] }} />,
    );
    expect(container.querySelector("img")).toBeNull();
    expect(container.textContent).toContain(evil);
  });

  it("says so when there is no explanation", () => {
    render(<ExplanationChart explanation={{}} />);
    expect(screen.getByText(/No explanation/)).toBeInTheDocument();
  });
});

describe("format helpers", () => {
  it("formats endpoints, protocols and percentages", () => {
    expect(endpoint("10.0.0.1", 80, 6)).toBe("10.0.0.1:80");
    expect(endpoint("fe80::1", 53, 17)).toBe("[fe80::1]:53");
    expect(endpoint("10.0.0.1", 0, 1)).toBe("10.0.0.1");
    expect(protocolName(6)).toBe("TCP");
    expect(protocolName(99)).toBe("99");
    expect(percent(0.934, 1)).toBe("93.4%");
    expect(percent(null)).toBe("—");
  });

  it("builds query strings without empty values", () => {
    expect(query({ a: "x", b: "", c: undefined, d: 0, e: null })).toBe("?a=x&d=0");
    expect(query({})).toBe("");
  });
});
