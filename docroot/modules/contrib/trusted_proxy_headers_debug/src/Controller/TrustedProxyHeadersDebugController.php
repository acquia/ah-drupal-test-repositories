<?php

namespace Drupal\trusted_proxy_headers_debug\Controller;

use Drupal\Component\Utility\Xss;
use Drupal\Core\Access\AccessResult;
use Drupal\Core\Controller\ControllerBase;
use Drupal\Core\Session\AccountInterface;
use Drupal\Core\Site\Settings;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Controller for Trusted Proxy Headers Debug routes.
 */
class TrustedProxyHeadersDebugController extends ControllerBase {

  const HEADER_FORWARDED = 0b00001; // When using RFC 7239.
  const HEADER_X_FORWARDED_FOR = 0b00010;
  const HEADER_X_FORWARDED_HOST = 0b00100;
  const HEADER_X_FORWARDED_PROTO = 0b01000;
  const HEADER_X_FORWARDED_PORT = 0b10000;

  // @deprecated since version 3.3, to be removed in 4.0
  const HEADER_CLIENT_IP = self::HEADER_X_FORWARDED_FOR;

  // @deprecated since version 3.3, to be removed in 4.0
  const HEADER_CLIENT_HOST = self::HEADER_X_FORWARDED_HOST;

  // @deprecated since version 3.3, to be removed in 4.0
  const HEADER_CLIENT_PROTO = self::HEADER_X_FORWARDED_PROTO;

  // @deprecated since version 3.3, to be removed in 4.0
  const HEADER_CLIENT_PORT = self::HEADER_X_FORWARDED_PORT;

  /**
   * Constants for Trusted Headers.
   */
  private static $trustedHeaderNames = [
    self::HEADER_FORWARDED => 'FORWARDED',
    self::HEADER_CLIENT_IP => 'X_FORWARDED_FOR',
    self::HEADER_CLIENT_HOST => 'X_FORWARDED_HOST',
    self::HEADER_CLIENT_PROTO => 'X_FORWARDED_PROTO',
    self::HEADER_CLIENT_PORT => 'X_FORWARDED_PORT',
  ];

  const UNTRUSTED = 'null (untrusted)';

  /**
   * Checks access for a specific request.
   *
   * @param \Drupal\Core\Session\AccountInterface $account
   *   Run access checks for this account.
   *
   * @return \Drupal\Core\Access\AccessResultInterface
   *   The access result.
   */
  public function access(AccountInterface $account) {
    $override = Settings::getInstance()->get('trusted_proxy_headers_debug_free_access');
    return AccessResult::allowedIf($override || $account->hasPermission('administer site configuration'));
  }

  /**
   * Report on Trusted Proxy Header configuration.
   */
  public function report() {
    $report['Settings'] = $this->getSettings();
    $report['Trusted Headers'] = $this->getTrustedHeaders();
    $report['Request Properties'] = $this->getRequestProperties();

    // Leaving these until the output can be filtered properly.
    // $report['HTTP Headers'] = $this->getHttpHeaders();
    // Avoid double-escaping of double-arrows in the arrays.
    // $report_html = str_replace('=&gt;', '=>',
    // Xss::filter(print_r($report, TRUE)));.
    // N.B. highlight_string does some escaping of HTML, but shouldn't be
    // trusted to avoid XSS. This should all go through twig.
    $report_html = print_r($report, TRUE);
    $report_html = highlight_string($report_html, TRUE);
    return new Response($report_html);
  }

  /**
   * Gets the Reverse Proxy Settings.
   *
   * @return array
   *   The Current Reverse Proxy Settings.
   */
  protected function getSettings() {
    // see: \Drupal\Core\StackMiddleware\ReverseProxyMiddleware::setSettingsOnRequest.
    $settings = Settings::getInstance();
    $proxy_settings = [];

    $proxy_settings['reverse_proxy'] = $settings->get('reverse_proxy', FALSE) ? 'TRUE' : 'FALSE';
    $proxy_settings['proxies'] = $settings->get('reverse_proxy_addresses', []);

    $proxy_header_settings = [
      'reverse_proxy_trusted_headers' => 'bitfield',
      'reverse_proxy_header' => Request::HEADER_X_FORWARDED_FOR,
      'reverse_proxy_proto_header' => Request::HEADER_X_FORWARDED_PROTO,
      'reverse_proxy_host_header' => Request::HEADER_X_FORWARDED_HOST,
      'reverse_proxy_port_header' => Request::HEADER_X_FORWARDED_PORT,
      'reverse_proxy_forwarded_header' => Request::HEADER_FORWARDED,
    ];

    foreach ($settings->getAll() as $k => $v) {
      if (in_array($k, array_keys($proxy_header_settings))) {
        if ($k == 'reverse_proxy_trusted_headers') {
          $proxy_settings[$k] = [
            'bitfield' => $v,
            'values' => $this->bitFieldToArray($v),
          ];
        }
        else {
          $proxy_settings[$k] = empty($v) ? self::UNTRUSTED : $v;
        }
      }
    }
    return $proxy_settings;
  }

  /**
   * Helper Method to output the available proxy values to an Array.
   */
  protected function bitFieldToArray($value) {
    // see: \Symfony\Component\HttpFoundation\Request::setTrustedProxies.
    $headers = [];
    foreach (self::$trustedHeaderNames as $header => $name) {
      $headers[$header] = $header & $value ? $name : NULL;
    }
    $headers = array_filter($headers);
    return $headers;
  }

  /**
   * Helper method to get the Trusted Headers.
   */
  protected function getTrustedHeaders() {
    $request = \Drupal::requestStack()->getCurrentRequest();
    $trustedHeaderSet = $request->getTrustedHeaderSet();
    return [
      'bitfield' => $trustedHeaderSet,
      'values' => $this->bitFieldToArray($trustedHeaderSet),
    ];
  }

  /**
   * Helper method to get the Request Properties.
   */
  protected function getRequestProperties() {
    $request = \Drupal::requestStack()->getCurrentRequest();
    $properties['Client IP'] = $request->getClientIp();
    $properties['Host'] = $request->getHost();
    $properties['Scheme'] = $request->getScheme();
    $properties['Port'] = $request->getPort();
    array_walk($properties, [Xss . 'filter']);
    return $properties;
  }

  /**
   * Helper method to get the HttpHeaders.
   */
  protected function getHttpHeaders() {
    // Need to be very careful about XSS here.
    $request = \Drupal::requestStack()->getCurrentRequest();
    return $request->headers->all();
  }
}
