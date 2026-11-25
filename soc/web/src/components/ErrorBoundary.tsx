import { Component, type ErrorInfo, type ReactNode } from "react";

/** Contains a crash to one page instead of blanking the whole dashboard. */
export default class ErrorBoundary extends Component<{ children: ReactNode; resetKey?: string },
  { error: Error | null }> {
  state = { error: null as Error | null };

  static getDerivedStateFromError(error: Error) {
    return { error };
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error("page crashed", error, info.componentStack);
  }

  componentDidUpdate(prev: { resetKey?: string }) {
    if (prev.resetKey !== this.props.resetKey && this.state.error) this.setState({ error: null });
  }

  render() {
    if (this.state.error) {
      return (
        <div className="card">
          <h2>This page couldn't be shown</h2>
          <p className="muted">Something in the data it received was unexpected. Other pages still work.</p>
        </div>
      );
    }
    return this.props.children;
  }
}
