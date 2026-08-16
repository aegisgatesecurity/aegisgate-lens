// AegisGate Lens — ot-protocols.js
//
// OT/ICS protocol detection patterns: Modbus, DNP3, OPC-UA.
// These patterns identify potential OT protocol manipulation in AI prompts,
// which is a high-risk indicator for manufacturing, energy, and utilities sectors.
//
// SOC relevance: If a user is prompting an AI with OT protocol commands,
// they may be testing industrial control manipulation (attack reconnaissance),
// troubleshooting legitimate OT systems (requires authorization), or attempting
// to bypass OT security controls.
//
// Apache 2.0. Copyright 2026 AegisGate Security, LLC.

(function (global) {
  'use strict';

  var patterns = {
        // Modbus Function Codes (manufacturing, building automation)
        // Function codes 01-07 are read operations (lower risk)
        // Function codes 05, 06, 15, 16 are write operations (higher risk)
        ot_modbus_function_code: {
          severity: 'medium',
          // Modbus function code 01-16 with label
          re: /(?:function\s*code|FC)\s*[:=]?\s*(?:0[1-7]|1[0-6])\b/gi
        },
        ot_modbus_write_single_coil: {
          severity: 'high',
          // Function code 05 (Write Single Coil) - potential control manipulation
          re: /(?:function\s*code|FC)\s*[:=]?\s*05\b/gi
        },
        ot_modbus_write_single_register: {
          severity: 'high',
          // Function code 06 (Write Single Register) - potential control manipulation
          re: /(?:function\s*code|FC)\s*[:=]?\s*06\b/gi
        },
        ot_modbus_write_multiple_coils: {
          severity: 'high',
          // Function code 15 (Write Multiple Coils) - potential control manipulation
          re: /(?:function\s*code|FC)\s*[:=]?\s*(?:15|0?15)\b/gi
        },
        ot_modbus_write_multiple_registers: {
          severity: 'high',
          // Function code 16 (Write Multiple Registers) - potential control manipulation
          re: /(?:function\s*code|FC)\s*[:=]?\s*(?:16|0?16)\b/gi
        },
        // DNP3 Control Operations (energy sector, grid control)
        ot_dnp3_control_relay: {
          severity: 'high',
          // DNP3 control relay output block (Group 12) - grid control operation
          re: /DNP3\s+(?:control\s+)?relay\s+(?:output\s+)?(?:block|group)\s*[:=]?\s*12\b/gi
        },
        ot_dnp3_analog_output: {
          severity: 'high',
          // DNP3 analog output block (Groups 40-42) - setpoint manipulation
          re: /DNP3\s+analog\s+output\s+(?:block|group)\s*[:=]?\s*4[0-2]\b/gi
        },
        // OPC-UA Method Calls (cross-industry industrial automation)
        ot_opcua_method_call: {
          severity: 'medium',
          // OPC-UA method call (Namespace.Method format)
          re: /OPC[-_]?UA\s+(?:method\s+)?[A-Za-z][A-Za-z0-9_]*\.[A-Za-z][A-Za-z0-9_]*\b/gi
        },
        ot_opcua_write_value: {
          severity: 'high',
          // OPC-UA WriteValue method call - potential control manipulation
          re: /WriteValue\s*(?:method)?\b/gi
        },
  };

  if (typeof self !== 'undefined') self.__lensOT_protocols = { patterns: patterns };
  if (typeof window !== 'undefined') window.__lensOT_protocols = { patterns: patterns };
  if (typeof globalThis !== 'undefined') {
    globalThis.__lensOT_protocols = { patterns: patterns };
  }
})(typeof self !== 'undefined' ? self : (typeof globalThis !== 'undefined' ? globalThis : this));
