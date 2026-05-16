// Licensed under the Apache License, Version 2.0
// Copyright 2025, Mindful Software LLC, All rights reserved.

import 'package:dartastic_opentelemetry/dartastic_opentelemetry.dart';

import 'otel_ipdata_suppression.dart';

const _tracerName = 'dartastic_otel_libs_ipdata';

Tracer _tracer() => OTel.tracerProvider().getTracer(_tracerName);

class IpdataResult {
  const IpdataResult({
    this.countryCode,
    this.asn,
    this.isTor,
    this.isProxy,
    this.isAnonymous,
    this.isKnownAttacker,
    this.isKnownAbuser,
    this.isThreat,
    this.isBogon,
    this.threatScore,
    this.itemsReturned,
    this.statusCode,
  });

  /// ISO 3166-1 alpha-2 (from `country_code`).
  final String? countryCode;

  /// `asn.asn` numeric portion.
  final int? asn;

  /// `threat.is_tor` — flags Tor exit nodes.
  final bool? isTor;

  /// `threat.is_proxy`.
  final bool? isProxy;

  /// `threat.is_anonymous` (VPN/proxy/Tor union).
  final bool? isAnonymous;

  /// `threat.is_known_attacker` — IP appears on attacker blocklists.
  final bool? isKnownAttacker;

  /// `threat.is_known_abuser` — spam/abuse blocklist hit.
  final bool? isKnownAbuser;

  /// `threat.is_threat` — ipdata's union threat flag.
  final bool? isThreat;

  /// `threat.is_bogon` — unallocated/reserved IP space.
  final bool? isBogon;

  /// Composite threat score (0-100) when surfaced.
  final int? threatScore;

  /// Number of IPs in a bulk response.
  final int? itemsReturned;

  final int? statusCode;
}

class IpdataCallResult<T> {
  const IpdataCallResult({required this.value, this.result});
  final T value;
  final IpdataResult? result;
}

/// Wraps an ipdata REST call in a CLIENT span. [operation] is one of
/// `lookup`, `bulk`, `carrier`, `asn`, `threat`.
Future<T> tracedIpdata<T>({
  required String operation,
  required Future<IpdataCallResult<T>> Function() invoke,
  String? plan,
}) async {
  if (ipdataInstrumentationSuppressed()) {
    final r = await invoke();
    return r.value;
  }
  final m = <String, Object>{
    'rpc.system': 'ipdata',
    'rpc.method': operation,
    'ipdata.operation': operation,
  };
  if (plan != null) m['ipdata.plan'] = plan;

  final span = _tracer().startSpan(
    'ipdata $operation',
    kind: SpanKind.client,
    attributes: OTel.attributesFromMap(m),
  );
  try {
    final r = await invoke();
    if (r.result != null) {
      final extras = <Attribute<Object>>[];
      if (r.result!.countryCode != null) {
        extras.add(
          OTel.attributeString(
            'ipdata.country.iso_code',
            r.result!.countryCode!,
          ),
        );
      }
      if (r.result!.asn != null) {
        extras.add(OTel.attributeInt('ipdata.asn', r.result!.asn!));
      }
      if (r.result!.isTor != null) {
        extras.add(
          OTel.attributeBool('ipdata.threat.is_tor', r.result!.isTor!),
        );
      }
      if (r.result!.isProxy != null) {
        extras.add(
          OTel.attributeBool('ipdata.threat.is_proxy', r.result!.isProxy!),
        );
      }
      if (r.result!.isAnonymous != null) {
        extras.add(
          OTel.attributeBool(
            'ipdata.threat.is_anonymous',
            r.result!.isAnonymous!,
          ),
        );
      }
      if (r.result!.isKnownAttacker != null) {
        extras.add(
          OTel.attributeBool(
            'ipdata.threat.is_known_attacker',
            r.result!.isKnownAttacker!,
          ),
        );
      }
      if (r.result!.isKnownAbuser != null) {
        extras.add(
          OTel.attributeBool(
            'ipdata.threat.is_known_abuser',
            r.result!.isKnownAbuser!,
          ),
        );
      }
      if (r.result!.isThreat != null) {
        extras.add(
          OTel.attributeBool('ipdata.threat.is_threat', r.result!.isThreat!),
        );
      }
      if (r.result!.isBogon != null) {
        extras.add(
          OTel.attributeBool('ipdata.threat.is_bogon', r.result!.isBogon!),
        );
      }
      if (r.result!.threatScore != null) {
        extras.add(
          OTel.attributeInt('ipdata.threat.score', r.result!.threatScore!),
        );
      }
      if (r.result!.itemsReturned != null) {
        extras.add(
          OTel.attributeInt('ipdata.items_returned', r.result!.itemsReturned!),
        );
      }
      if (r.result!.statusCode != null) {
        extras.add(
          OTel.attributeInt('http.response.status_code', r.result!.statusCode!),
        );
        if (r.result!.statusCode! >= 400) {
          span.setStatus(
            SpanStatusCode.Error,
            'ipdata HTTP ${r.result!.statusCode}',
          );
        }
      }
      if (extras.isNotEmpty) span.addAttributes(OTel.attributes(extras));
    }
    return r.value;
  } catch (e, st) {
    span.addAttributes(
      OTel.attributes([
        OTel.attributeString(
          ErrorResource.errorType.key,
          e.runtimeType.toString(),
        ),
      ]),
    );
    span.recordException(e, stackTrace: st);
    span.setStatus(SpanStatusCode.Error, e.toString());
    rethrow;
  } finally {
    span.end();
  }
}
