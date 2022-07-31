import 'package:ngdart/src/utilities.dart';

import 'package:ngdart/di.dart' show Injectable;
import 'html_sanitizer.dart';
import 'style_sanitizer.dart';
import 'url_sanitizer.dart';
import 'sanitization_service.dart';

abstract class SafeValue {}

abstract class SafeHtml extends SafeValue {}

abstract class SafeStyle extends SafeValue {}

abstract class SafeUrl extends SafeValue {}

abstract class SafeResourceUrl extends SafeValue {}

/// DomSanitizationService helps preventing Cross Site Scripting Security bugs
/// (XSS) by sanitizing values to be safe to use in the different DOM contexts.
///
/// For example, when binding a URL in an `<a [href]="someUrl">` hyperlink,
/// _someUrl_ will be sanitized so that an attacker cannot inject a
/// `javascript:` URL that would execute code on the website.
///
/// In specific situations, it might be necessary to disable sanitization, for
/// example if the application genuinely needs to produce a javascript:
/// style link with a dynamic value in it.
///
/// Users can bypass security by constructing a value with one of the
/// `bypassSecurityTrust...` methods, and then binding to that value from the
/// template.
///
/// These situations should be very rare, and extraordinary care must be taken
/// to avoid creating a Cross Site Scripting (XSS) security bug!
///
/// When using `bypassSecurityTrust...`, make sure to call the method as
/// early as possible and as close as possible to the source of the value,
/// to make it easy to verify that no security bug is created by its use.
///
/// It is not required (and not recommended) to bypass security if the value
/// is safe, for example, a URL that does not start with a suspicious protocol, or an
/// HTML snippet that does not contain dangerous code. The sanitizer leaves
/// safe values intact.
@Injectable()
class DomSanitizationService implements SanitizationService {
  static const _instance = DomSanitizationService._();

  // Force a global static singleton across DDC instances for this service. In
  // angular currently it is already a single instance across all instances for
  // performance reasons. This allows a check to occur that this is really the
  // same sanitizer is used.
  factory DomSanitizationService() => _instance;

  // Const to enforce statelessness.
  const DomSanitizationService._();

  @override
  String? sanitizeHtml(value) {
    if (value == null) return null;
    if (value is SafeHtmlImpl) return value.changingThisWillBypassSecurityTrust;
    if (value is SafeValue) {
      throw UnsupportedError(
          'Unexpected SecurityContext $value, expecting html');
    }
    return sanitizeHtmlInternal(unsafeCast(value));
  }

  @override
  String? sanitizeStyle(value) {
    if (value == null) return null;
    if (value is SafeStyleImpl) {
      return value.changingThisWillBypassSecurityTrust;
    }
    if (value is SafeValue) {
      throw UnsupportedError('Unexpected SecurityContext $value, '
          'expecting style');
    }
    if (value == null) return null;
    return internalSanitizeStyle(value is String ? value : value.toString());
  }

  @override
  String? sanitizeUrl(value) {
    if (value == null) return null;
    if (value is SafeUrlImpl) return value.changingThisWillBypassSecurityTrust;
    if (value is SafeValue) {
      throw UnsupportedError('Unexpected SecurityContext $value, '
          'expecting url');
    }
    return internalSanitizeUrl(value.toString());
  }

  @override
  String? sanitizeResourceUrl(value) {
    if (value == null) return null;
    if (value is SafeResourceUrlImpl) {
      return value.changingThisWillBypassSecurityTrust;
    }
    if (value is SafeValue) {
      throw UnsupportedError('Unexpected SecurityContext $value, '
          'expecting resource url');
    }
    throw UnsupportedError(
        'Security violation in resource url. Create SafeValue');
  }

  /// Bypass security and trust the given value to be safe HTML.
  ///
  /// Only use this when the bound HTML is unsafe (e.g. contains `<script>`
  /// tags) and the code should be executed. The sanitizer will leave safe HTML
  /// intact, so in most situations this method should not be used.
  ///
  /// WARNING: calling this method with untrusted user data will cause severe
  /// security bugs!
  SafeHtml bypassSecurityTrustHtml(String? value) => SafeHtmlImpl(value ?? '');

  /// Bypass security and trust the given value to be safe style value (CSS).
  ///
  /// WARNING: calling this method with untrusted user data will cause severe
  /// security bugs!
  SafeStyle bypassSecurityTrustStyle(String? value) =>
      SafeStyleImpl(value ?? '');

  /// Bypass security and trust the given value to be a safe style URL, i.e. a
  /// value that can be used in hyperlinks or `<iframe src>`.
  ///
  /// WARNING: calling this method with untrusted user data will cause severe
  /// security bugs!
  SafeUrl bypassSecurityTrustUrl(String? value) => SafeUrlImpl(value ?? '');

  /// Bypass security and trust the given value to be a safe resource URL, i.e.
  /// a location that may be used to load executable code from, like
  /// <script src>.
  ///
  /// WARNING: calling this method with untrusted user data will cause severe
  /// security bugs!
  SafeResourceUrl bypassSecurityTrustResourceUrl(String? value) =>
      SafeResourceUrlImpl(value ?? '');
}

abstract class SafeValueImpl implements SafeValue {
  /// Named this way to allow security teams to
  /// to search for BypassSecurityTrust across code base.
  final String changingThisWillBypassSecurityTrust;
  SafeValueImpl(this.changingThisWillBypassSecurityTrust);

  @override
  String toString() => changingThisWillBypassSecurityTrust;
}

class SafeHtmlImpl extends SafeValueImpl implements SafeHtml {
  SafeHtmlImpl(String value) : super(value);
}

class SafeStyleImpl extends SafeValueImpl implements SafeStyle {
  SafeStyleImpl(String value) : super(value);
}

class SafeUrlImpl extends SafeValueImpl implements SafeUrl {
  SafeUrlImpl(String value) : super(value);
}

class SafeResourceUrlImpl extends SafeValueImpl implements SafeResourceUrl {
  SafeResourceUrlImpl(String value) : super(value);
}
