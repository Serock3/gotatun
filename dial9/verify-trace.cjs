// Smoke-check a downloaded profile with the installed Dial9 CLI's bundled toolkit.
// Usage: node dial9/verify-trace.cjs <toolkit directory> <trace directory>
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

async function main() {
  const [toolkit, directory] = process.argv.slice(2).map(p => path.resolve(p));
  assert(toolkit && directory, 'expected toolkit and trace directories');
  const { analyzeTraces } = require(path.join(toolkit, 'analyze.js'));
  const { parseTrace } = require(path.join(toolkit, 'trace_parser.js'));
  const files = fs.readdirSync(directory)
    .filter(name => /^trace\.\d+\.bin(?:\.gz)?$/.test(name))
    .sort((a, b) => Number(a.split('.')[1]) - Number(b.split('.')[1]));
  assert(files.length > 0, 'no trace segments');
  files.forEach((file, i) => assert.equal(Number(file.split('.')[1]), i,
    'missing segments: the rolling buffer may have discarded the beginning'));
  const manifest = JSON.parse(fs.readFileSync(path.join(directory, 'run.json')));
  assert.equal(manifest.status, 'success', 'controller reported a failed run');

  // Aggregate analysis first, following the CLI's trace-loading skill. Analyze individual
  // segments to avoid the 0.5.6 directory worker's JSON stdout failure on large results.
  for (const file of files) {
    const summary = await analyzeTraces(path.join(directory, file));
    console.log(`${file}: ${summary.eventCount} task events; ${summary.cpuSampleCount} CPU samples`);
  }

  const markers = [];
  const samples = [];
  const backends = new Set();
  let tracingEvents = 0;
  for (const file of files) {
    for await (const trace of parseTrace(path.join(directory, file))) {
      assert(!trace.truncated && !trace.incompleteFiles, `${file}: incomplete parser result`);
      // The pinned rc0 writer predates segment.complete metadata. Honor an explicit
      // incomplete flag when present; use workload/shutdown markers for older traces.
      for (const [key, value] of trace.segmentMetadata) {
        if (key === 'cpu.profile.backend') backends.add(value);
      }
      for (const event of trace.customEvents) {
        if (event.name.endsWith('WorkloadEvent')) markers.push(event);
        if (event.name.endsWith('TracingEventRecord')) {
          assert(event.fields.level && event.fields.target && event.fields.fields, 'invalid tracing event');
          tracingEvents++;
        }
      }
      for (const sample of trace.cpuSamples) {
        if (sample.source !== 0) continue;
        const hasGotatunFrame = sample.callchain.some(address => {
          const frames = trace.callframeSymbols.get(address);
          return (Array.isArray(frames) ? frames : [frames])
            .some(frame => frame?.symbol?.includes('gotatun::'));
        });
        samples.push({ timestamp: sample.timestamp, hasGotatunFrame });
      }
    }
  }
  assert(tracingEvents > 0, 'no converted tracing events');
  console.log(`${tracingEvents} converted tracing events with fields and source metadata`);
  assert(markers.some(event => event.fields.phase === 'shutdown'), 'missing orderly tunnel shutdown');
  for (const direction of ['send', 'receive']) {
    const phase = name => markers.filter(event => event.fields.phase === name &&
      event.fields.detail.split(', ').includes(`direction=${direction}`));
    const starts = phase('iperf_started');
    const finishes = phase('iperf_finished');
    assert.equal(starts.length, 1, `${direction}: expected one start`);
    assert.equal(finishes.length, 1, `${direction}: expected one finish`);
    const duration = (finishes[0].timestamp - starts[0].timestamp) / 1e9;
    assert(duration >= manifest.seconds_per_direction * 0.9, `${direction}: transfer too short`);
    const during = samples.filter(sample => sample.timestamp >= starts[0].timestamp &&
      sample.timestamp <= finishes[0].timestamp);
    assert(during.length > 0, `${direction}: no on-CPU samples`);
    assert(during.some(sample => sample.hasGotatunFrame), `${direction}: no symbolized GotaTun stacks`);
    console.log(`${direction}: ${duration.toFixed(2)} s; ${during.length} on-CPU samples; symbolized GotaTun stacks present`);
  }
  assert(backends.size > 0, 'missing CPU backend metadata');
  console.log(`Validated ${manifest.source_sha}; CPU backend: ${[...backends].join(', ')}`);
}

main().catch(error => { console.error(error.message); process.exitCode = 1; });
