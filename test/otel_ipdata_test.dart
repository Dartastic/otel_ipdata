// Licensed under the Dartastic Pro Software License Agreement.
// Copyright 2025-2026 Mindful Software LLC d/b/a Dartastic.io, All rights reserved.

import 'package:dartastic_opentelemetry/dartastic_opentelemetry.dart';
import 'package:dartastic_opentelemetry/testing.dart';
import 'package:otel_ipdata/otel_ipdata.dart';
import 'package:test/test.dart';

void main() {
  late TestHarness harness;
  late InMemorySpanExporter spans;

  setUpAll(() async {
    harness = await maybeInitializeOtelForTest(serviceName: 'otel_ipdata-test');
    spans = harness.spans;
  });

  setUp(() => harness.clear());

  Map<String, Object> attrsOf(Span s) => {
    for (final a in s.attributes.toList()) a.key: a.value,
  };

  test('threat lookup records known_attacker + score', () async {
    await tracedIpdata<String>(
      operation: 'threat',
      plan: 'pro',
      invoke: () async => const IpdataCallResult(
        value: 'ok',
        result: IpdataResult(
          countryCode: 'RU',
          asn: 1234,
          isTor: false,
          isKnownAttacker: true,
          isKnownAbuser: true,
          isThreat: true,
          isBogon: false,
          threatScore: 87,
          statusCode: 200,
        ),
      ),
    );
    final a = attrsOf(spans.findSpanByName('ipdata threat')!);
    expect(a['ipdata.operation'], 'threat');
    expect(a['ipdata.plan'], 'pro');
    expect(a['ipdata.threat.is_known_attacker'], true);
    expect(a['ipdata.threat.is_known_abuser'], true);
    expect(a['ipdata.threat.score'], 87);
    expect(a['ipdata.country.iso_code'], 'RU');
  });

  test('bulk records items_returned', () async {
    await tracedIpdata<String>(
      operation: 'bulk',
      invoke: () async => const IpdataCallResult(
        value: 'ok',
        result: IpdataResult(itemsReturned: 100),
      ),
    );
    final a = attrsOf(spans.findSpanByName('ipdata bulk')!);
    expect(a['ipdata.items_returned'], 100);
  });

  test('suppression skips spans', () async {
    await runWithoutIpdataInstrumentationAsync(() async {
      await tracedIpdata<String>(
        operation: 'lookup',
        invoke: () async => const IpdataCallResult(value: 'v'),
      );
    });
    expect(spans.findSpansStartingWith('ipdata '), isEmpty);
  });
}
