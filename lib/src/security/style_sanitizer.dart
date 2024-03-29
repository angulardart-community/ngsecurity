import 'dart:html';

import 'package:ngdart/src/utilities.dart';

import 'url_sanitizer.dart';

/// Regular expression for safe style values.
///
/// Quotes (" and ') are allowed, but a check must be done elsewhere to ensure
/// they're balanced.
///
/// ',' allows multiple values to be assigned to the same property
/// (e.g. background-attachment or font-family) and hence could allow
/// multiple values to get injected, but that should pose no risk of XSS.
///
/// The function expression checks only for XSS safety, not for CSS validity.
///
/// This regular expression was taken from the Closure sanitization library and
/// augmented for transformation values.
const _VALUES = '[-,."\'%_!# a-zA-Z0-9]+';
const _TRANSFORMATION_FNS =
    '(?:matrix|translate|scale|rotate|skew|perspective)(?:X|Y|3d)?';
const _COLOR_FNS = '(?:rgb|hsl)a?';
const _FN_ARGS = '\\([-0-9.%, a-zA-Z]+\\)';
const _KEY = '([a-zA-Z-]+[ ]?\\:)';

final RegExp _safeStyleValue =
    RegExp('^($_VALUES|($_KEY$_VALUES[ ;]?)|((?:$_TRANSFORMATION_FNS|'
        '$_COLOR_FNS)$_FN_ARGS)[ ;]?)+\$');

/// Matches a `url(...)` value with an arbitrary argument as long as it does
/// not contain parentheses.
///
/// The URL value still needs to be sanitized separately.
///
/// `url(...)` values are a very common use case, e.g. for `background-image`.
/// With carefully crafted CSS style rules, it is possible to construct an
/// information leak with `url` values in CSS, e.g. by observing whether
/// scroll bars are displayed, or character ranges used by a font face
/// definition.
///
/// Angular only allows binding CSS values (as opposed to entire CSS rules),
/// so it is unlikely that binding a URL value without further cooperation
/// from the page will cause an information leak, and if so, it is just a leak,
/// not a full blown XSS vulnerability.
///
/// Given the common use case, low likelihood of attack vector, and low impact
/// of an attack, this code is permissive and allows URLs that sanitize
/// otherwise.
final RegExp _urlRe = RegExp(r'^url\([^)]+\)$');

/// Checks that quotes (" and ') are properly balanced inside a string. Assumes
/// that neither escape (\) nor any other character that could result in
/// breaking out of a string parsing context are allowed;
/// see http://www.w3.org/TR/css3-syntax/#string-token-diagram.
///
/// This code was taken from the Closure sanitization library.

bool _hasBalancedQuotes(String value) {
  final quoteCodeUnit = "'".codeUnitAt(0);
  final doubleQuoteCodeUnit = '"'.codeUnitAt(0);
  var outsideSingle = true;
  var outsideDouble = true;
  for (var i = 0; i < value.length; i++) {
    var c = value.codeUnitAt(i);
    if (c == quoteCodeUnit && outsideDouble) {
      outsideSingle = !outsideSingle;
    } else if (c == doubleQuoteCodeUnit && outsideSingle) {
      outsideDouble = !outsideDouble;
    }
  }
  return outsideSingle && outsideDouble;
}

String internalSanitizeStyle(String value) {
  value = value.trim();
  if (value.isEmpty) return '';
  // Single url(...) values are supported, but only for URLs that sanitize
  // cleanly. See above for reasoning behind this.
  Match? urlMatch = _urlRe.firstMatch(value);
  if (urlMatch != null) {
    var input = urlMatch.group(0)!;
    if (internalSanitizeUrl(input) == input) {
      return value; // Safe style values.
    }
  } else if (_safeStyleValue.hasMatch(value) && _hasBalancedQuotes(value)) {
    return value;
  }
  if (value.contains(';')) {
    var parts = value.split(';');
    var failed = false;
    for (var part in parts) {
      Match? urlMatch = _urlRe.firstMatch(part);
      if (urlMatch != null) {
        var input = urlMatch.group(0)!;
        if (internalSanitizeUrl(input) != input) {
          failed = true;
          break;
        }
      } else if (!(_safeStyleValue.hasMatch(part) == true &&
          _hasBalancedQuotes(part))) {
        failed = true;
        break;
      }
    }
    if (!failed) return value;
  }
  if (isDevMode) {
    window.console.warn('Sanitizing unsafe style value $value '
        '(see http://g.co/ng/security#xss).');
  }
  return 'unsafe';
}
