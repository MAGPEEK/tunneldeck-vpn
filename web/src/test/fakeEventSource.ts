/** A controllable stand-in for EventSource; tests drive it through `emit`, `fail` and `open`. */
export class FakeEventSource extends EventTarget {
  static instances: FakeEventSource[] = [];

  static latest(): FakeEventSource {
    const source = FakeEventSource.instances.at(-1);
    if (!source) {
      throw new Error('no EventSource was opened');
    }
    return source;
  }

  static reset(): void {
    FakeEventSource.instances = [];
  }

  readonly url: string;
  readyState = 0;

  constructor(url: string | URL) {
    super();
    this.url = String(url);
    FakeEventSource.instances.push(this);
  }

  open(): void {
    this.readyState = 1;
    this.dispatchEvent(new Event('open'));
  }

  emit(type: string, data: unknown): void {
    this.dispatchEvent(new MessageEvent(type, { data: JSON.stringify(data) }));
  }

  fail(): void {
    this.dispatchEvent(new Event('error'));
  }

  close(): void {
    this.readyState = 2;
  }
}
