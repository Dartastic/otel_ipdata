// Licensed under the Apache License, Version 2.0
// Copyright 2025-2026 Mindful Software LLC d/b/a Dartastic.io, All rights reserved.

import 'package:dartastic_opentelemetry/dartastic_opentelemetry.dart';
import 'package:otel_ipdata/otel_ipdata.dart';

/// Traces ipdata calls with OpenTelemetry.
///
/// `otel_ipdata` depends on the OpenTelemetry API only, so the application
/// initializes an SDK once at startup. Wrap each ipdata call in
/// [tracedIpdata]; the `invoke` callback makes the real call and reports what
/// came back, which is recorded on the span.
Future<void> main() async {
  await OTel.initialize(serviceName: 'ipdata-example');

  // Wraps an ipdata REST call in a CLIENT span.
  final ipdataId = await tracedIpdata<String>(
    operation: 'create',
    plan: 'example',
    invoke: () async {
      // Make the ipdata call here, then report what it returned.
      const id = 'ipdata_8f3a2c';
      return const IpdataCallResult(
          value: id,
          result: IpdataResult(
              countryCode: 'country_code',
              asn: 1,
              isTor: true,
              isProxy: true,
              isAnonymous: true,
              isKnownAttacker: true,
              isKnownAbuser: true,
              isThreat: true,
              isBogon: true,
              threatScore: 1,
              itemsReturned: 120,
              statusCode: 201));
    },
  );
  OTelLog.info('tracedIpdata create returned $ipdataId');

  // Calls that should not be traced, such as health checks, run inside
  // runWithoutIpdataInstrumentationAsync.
  await runWithoutIpdataInstrumentationAsync(
    () => tracedIpdata<String>(
      operation: 'create',
      plan: 'example',
      invoke: () async {
        const id = 'ipdata_8f3a2c';
        return const IpdataCallResult(
            value: id,
            result: IpdataResult(
                countryCode: 'country_code',
                asn: 1,
                isTor: true,
                isProxy: true,
                isAnonymous: true,
                isKnownAttacker: true,
                isKnownAbuser: true,
                isThreat: true,
                isBogon: true,
                threatScore: 1,
                itemsReturned: 120,
                statusCode: 201));
      },
    ),
  );

  await OTel.shutdown();
}
