/**
 * SiteCure Admin JavaScript Controller
 * Pure vanilla jQuery handling chunked batched scanning, modals, and actions
 */
(function ($) {
  'use strict';

  var sitecure_data = window.sitecure_data || {};
  var currentScanId = 0;
  var isScanning = false;

  $(document).ready(function () {
    // 1. Scan Trigger
    $('#wpd-btn-start-scan').on('click', function (e) {
      e.preventDefault();
      if (isScanning) return;

      var siteId = $('#wpd-select-site').val() || 1;
      var scanType = $('#wpd-select-type').val() || 'deep';

      startScan(siteId, scanType);
    });

    // 2. View Code Modal
    $(document).on('click', '.wpd-btn-view-code', function (e) {
      e.preventDefault();
      var findingId = $(this).data('id');
      viewCodeModal(findingId);
    });

    $('.wpd-modal-close, .wpd-modal-backdrop').on('click', function (e) {
      if (e.target === this) {
        $('#wpd-code-modal').fadeOut(150, function () {
          $(this).removeClass('is-active');
        });
      }
    });

    // 3. Clean / Neutralize Injected Code Action
    $(document).on('click', '.wpd-btn-clean', function (e) {
      e.preventDefault();
      var btn = $(this);
      var findingId = btn.data('id');

      if (!confirm('Are you sure you want to clean this threat? SiteCure will create a safety backup in Quarantine Vault and safely neutralize the malicious code/spam.')) {
        return;
      }

      btn.prop('disabled', true).text('Cleaning...');

      $.post(sitecure_data.ajax_url, {
        action: 'sitecure_clean_file',
        nonce: sitecure_data.nonce,
        finding_id: findingId
      }, function (res) {
        if (res.success) {
          alert('Threat successfully cleaned! Safety backup safely preserved in Quarantine Storage Vault.');
          location.reload();
        } else {
          alert('Clean error: ' + (res.data ? res.data.message : 'Unknown error'));
          btn.prop('disabled', false).text('Clean');
        }
      });
    });

    // 4. Quarantine File Action
    $(document).on('click', '.wpd-btn-quarantine', function (e) {
      e.preventDefault();
      var btn = $(this);
      var findingId = btn.data('id');

      if (!confirm(sitecure_data.strings.confirm_q)) {
        return;
      }

      btn.prop('disabled', true).text('Quarantining...');

      $.post(sitecure_data.ajax_url, {
        action: 'sitecure_quarantine_file',
        nonce: sitecure_data.nonce,
        finding_id: findingId
      }, function (res) {
        if (res.success) {
          alert('File quarantined safely! Original is backed up in protected vault.');
          location.reload();
        } else {
          alert('Error: ' + (res.data ? res.data.message : 'Unknown error'));
          btn.prop('disabled', false).text('Quarantine');
        }
      });
    });

    // 4. Restore File Action
    $(document).on('click', '.wpd-btn-restore', function (e) {
      e.preventDefault();
      var btn = $(this);
      var qId = btn.data('id');

      if (!confirm(sitecure_data.strings.confirm_r)) {
        return;
      }

      btn.prop('disabled', true).text('Restoring...');

      $.post(sitecure_data.ajax_url, {
        action: 'sitecure_restore_file',
        nonce: sitecure_data.nonce,
        quarantine_id: qId
      }, function (res) {
        if (res.success) {
          alert('File restored successfully!');
          location.reload();
        } else {
          alert('Error: ' + (res.data ? res.data.message : 'Unknown error'));
          btn.prop('disabled', false).text('Restore');
        }
      }).fail(function (xhr) {
        var msg = (xhr.responseJSON && xhr.responseJSON.data && xhr.responseJSON.data.message) ? xhr.responseJSON.data.message : 'Server returned status ' + xhr.status;
        alert('Restore failed: ' + msg);
        btn.prop('disabled', false).text('Restore');
      });
    });

    // 5. Repair Core File Action
    $(document).on('click', '.wpd-btn-repair-core', function (e) {
      e.preventDefault();
      var btn = $(this);
      var filePath = btn.data('path');
      var siteId = btn.data('site') || 0;

      if (!confirm(sitecure_data.strings.confirm_c)) {
        return;
      }

      btn.prop('disabled', true).text('Downloading...');

      $.post(sitecure_data.ajax_url, {
        action: 'sitecure_repair_core',
        nonce: sitecure_data.nonce,
        file_path: filePath,
        site_id: siteId
      }, function (res) {
        if (res.success) {
          alert('Core file repaired with official pristine copy from WordPress.org!');
          location.reload();
        } else {
          alert('Error: ' + (res.data ? res.data.message : 'Unknown error'));
          btn.prop('disabled', false).text('Repair Core');
        }
      });
    });

    // 6. Verify Site Health Action
    $('#wpd-btn-verify-site').on('click', function (e) {
      e.preventDefault();
      var btn = $(this);
      btn.prop('disabled', true).text('Verifying...');

      $.post(sitecure_data.ajax_url, {
        action: 'sitecure_verify_site',
        nonce: sitecure_data.nonce
      }, function (res) {
        btn.prop('disabled', false).text('Run Health Verification');
        if (res.success) {
          var r = res.data;
          var msg = 'Verification Complete!\nStatus: ' + r.status.toUpperCase() + '\nResponse Time: ' + r.response_ms + 'ms\n\nChecks:\n';
          for (var k in r.checks) {
            msg += '• ' + k + ': ' + r.checks[k].message + '\n';
          }
          alert(msg);
        } else {
          alert('Verification failed to execute.');
        }
      });
    });

    // 7. Add Site Form Toggle & Submit (Quota Protected)
    $('#wpd-btn-show-add-site').on('click', function () {
      var canAdd = $(this).data('can-add');
      if (canAdd === 0 || canAdd === '0') {
        $('#wpd-pro-upgrade-modal').addClass('is-active').css('display', 'flex').hide().fadeIn(150);
      } else {
        $('#wpd-add-site-card').slideToggle(200);
      }
    });

    $(document).on('click', '#wpd-btn-onboard-external', function () {
      $('#wpd-add-site-card').slideDown(200);
      $('html, body').animate({ scrollTop: $('#wpd-add-site-card').offset().top - 80 }, 300);
    });

    $(document).on('click', '.wpd-btn-open-pro-modal', function () {
      $('#wpd-pro-upgrade-modal').addClass('is-active').css('display', 'flex').hide().fadeIn(150);
    });

    $(document).on('click', '.wpd-modal-close', function () {
      $(this).closest('.wpd-modal-backdrop').fadeOut(150, function () {
        $(this).removeClass('is-active');
      });
    });

    // 1-Click Register Local Hosted Site
    $(document).on('click', '#wpd-btn-register-local', function (e) {
      e.preventDefault();
      var btn = $(this);
      btn.prop('disabled', true).text('Registering site...');

      $.post(sitecure_data.ajax_url, {
        action: 'sitecure_register_local_site',
        nonce: sitecure_data.nonce
      }, function (res) {
        if (res.success) {
          alert(res.data.message);
          window.location.href = 'admin.php?page=sitecure-findings&site_id=' + res.data.site_id;
        } else {
          alert('Error: ' + (res.data ? res.data.message : 'Could not register site.'));
          btn.prop('disabled', false).html('<span class="dashicons dashicons-controls-play"></span> Scan This Hosted Website');
        }
      });
    });

    // Delete Site
    $(document).on('click', '.wpd-btn-delete-site', function (e) {
      e.preventDefault();
      var btn = $(this);
      var siteId = btn.data('id');
      var siteName = btn.data('name');

      if (!confirm('Are you sure you want to remove "' + siteName + '"? This will free up your active site slot.')) {
        return;
      }

      btn.prop('disabled', true);
      $.post(sitecure_data.ajax_url, {
        action: 'sitecure_delete_site',
        nonce: sitecure_data.nonce,
        site_id: siteId
      }, function (res) {
        if (res.success) {
          alert(res.data.message);
          location.reload();
        } else {
          alert('Error: ' + (res.data ? res.data.message : 'Could not delete site.'));
          btn.prop('disabled', false);
        }
      });
    });

    // Pro Waitlist Opt-in
    $(document).on('click', '#wpd-btn-join-pro', function (e) {
      e.preventDefault();
      var email = $('#wpd-pro-email').val().trim();
      if (!email) {
        alert('Please enter your email address.');
        return;
      }
      $('#wpd-pro-waitlist-msg').html('<span class="dashicons dashicons-yes" style="color:#059669;vertical-align:middle;"></span> Thank you! You are on the early VIP Pro waitlist.').fadeIn();
      $('#wpd-btn-join-pro').prop('disabled', true).text('Added!');
    });

    // Activate License Key
    $(document).on('click', '#wpd-btn-activate-license', function (e) {
      e.preventDefault();
      var key = $('#wpd-license-key').val().trim();
      if (!key) {
        alert('Please enter a license key.');
        return;
      }
      var btn = $(this);
      btn.prop('disabled', true).text('Activating...');

      $.post(sitecure_data.ajax_url, {
        action: 'sitecure_activate_license',
        nonce: sitecure_data.nonce,
        license_key: key
      }, function (res) {
        if (res.success) {
          $('#wpd-license-status-msg').css('color', '#059669').text(res.data.message).show();
          setTimeout(function () {
            location.reload();
          }, 900);
        } else {
          $('#wpd-license-status-msg').css('color', '#dc2626').text(res.data ? res.data.message : 'Activation failed.').show();
          btn.prop('disabled', false).text('Activate Key');
        }
      });
    });

    // Deactivate License Key (1-Click revert to Free plan)
    $(document).on('click', '#wpd-btn-deactivate-license', function (e) {
      e.preventDefault();
      if (!confirm('Are you sure you want to deactivate your license and revert back to the Free plan (1 active site)?')) {
        return;
      }
      var btn = $(this);
      btn.prop('disabled', true).text('Deactivating...');

      $.post(sitecure_data.ajax_url, {
        action: 'sitecure_deactivate_license',
        nonce: sitecure_data.nonce
      }, function (res) {
        if (res.success) {
          location.reload();
        } else {
          alert(res.data ? res.data.message : 'Deactivation failed.');
          btn.prop('disabled', false).text('Deactivate Key');
        }
      });
    });

    $('#wpd-form-add-site').on('submit', function (e) {
      e.preventDefault();
      var form = $(this);
      var data = form.serialize() + '&action=sitecure_save_site&nonce=' + sitecure_data.nonce;

      $.post(sitecure_data.ajax_url, data, function (res) {
        if (res.success) {
          alert(res.data.message);
          location.reload();
        } else {
          if (res.data && res.data.code === 'quota_reached') {
            $('#wpd-pro-upgrade-modal').addClass('is-active').css('display', 'flex').hide().fadeIn(150);
          } else {
            alert('Error: ' + (res.data ? res.data.message : 'Unknown error'));
          }
        }
      });
    });
  });

  /**
   * Start Scan Pipeline
   */
  function startScan(siteId, scanType) {
    isScanning = true;
    $('#wpd-btn-start-scan').prop('disabled', true).text('Initializing...');
    $('#wpd-scan-terminal').empty();
    logTerminal('Initializing emergency scan pipeline...', 'log-warning');

    $.post(sitecure_data.ajax_url, {
      action: 'sitecure_start_scan',
      nonce: sitecure_data.nonce,
      site_id: siteId,
      scan_type: scanType
    }, function (res) {
      if (!res.success) {
        alert('Failed to start scan: ' + (res.data ? res.data.message : 'Unknown error'));
        resetScanState();
        return;
      }

      currentScanId = res.data.scan_id;
      var total = res.data.total_files;
      var b = res.data.breakdown;
      if (b) {
        logTerminal('Cataloged ' + total + ' files across whole site: Plugins (' + b.plugins + '), Themes (' + b.themes + '), Uploads (' + b.uploads + '), Core (' + b.core + '), Custom/Root (' + b.custom + ')', 'log-success');
      } else {
        logTerminal('Cataloged ' + total + ' files across site. Starting chunked inspection batches...', 'log-success');
      }

      $('#wpd-scan-progress-box').slideDown(200);
      runBatch(currentScanId, 120);
    }).fail(function () {
      alert('Server connection error.');
      resetScanState();
    });
  }

  /**
   * Process scan in batches of files
   */
  function runBatch(scanId, batchSize) {
    $.post(sitecure_data.ajax_url, {
      action: 'sitecure_batch_scan',
      nonce: sitecure_data.nonce,
      scan_id: scanId,
      batch_size: batchSize
    }, function (res) {
      if (!res.success) {
        logTerminal('Batch error: ' + (res.data ? res.data.message : 'Error'), 'log-danger');
        resetScanState();
        return;
      }

      var d = res.data;
      var pct = d.percentage;
      $('#wpd-progress-bar').css('width', pct + '%');
      $('#wpd-progress-text').text(pct + '%');
      $('#wpd-scanned-count').text(d.scanned_files + ' / ' + d.total_files + ' files');
      $('#wpd-findings-count').text(d.findings_count + ' findings detected');

      var folderMsg = d.current_folder ? ' [' + d.current_folder + ']' : '';
      logTerminal('Scanned ' + d.scanned_files + ' / ' + d.total_files + ' files (' + pct + '%)' + folderMsg + '... Findings: ' + d.findings_count);

      if (d.is_completed) {
        logTerminal('Scan completed! Finalizing persistence & database forensics...', 'log-success');
        $('#wpd-progress-bar').css('width', '100%');
        $('#wpd-progress-text').text('100%');
        setTimeout(function () {
          alert('Scan Completed! Total findings: ' + d.findings_count);
          location.reload();
        }, 800);
      } else {
        // Next chunk immediately
        runBatch(scanId, batchSize);
      }
    }).fail(function () {
      logTerminal('Network timeout or disconnect during batch. Retrying chunk...', 'log-warning');
      setTimeout(function () {
        runBatch(scanId, batchSize);
      }, 2000);
    });
  }

  function resetScanState() {
    isScanning = false;
    $('#wpd-btn-start-scan').prop('disabled', false).text('Start Emergency Scan');
  }

  function logTerminal(msg, cssClass) {
    var term = $('#wpd-scan-terminal');
    var time = new Date().toLocaleTimeString();
    var span = $('<div class="' + (cssClass || '') + '">[' + time + '] ' + msg + '</div>');
    term.append(span);
    term.scrollTop(term[0].scrollHeight);
  }

  function viewCodeModal(findingId) {
    $('#wpd-code-modal-content').html('<div style="padding:30px;text-align:center;color:#94a3b8;"><span class="dashicons dashicons-update spin"></span> Loading code evidence...</div>');
    $('#wpd-code-modal-evidence-box').hide();
    $('#wpd-code-modal-actions').empty();
    $('#wpd-code-modal-status-text').text('Loading threat details...');

    // Enforce centered viewport modal
    $('#wpd-code-modal').addClass('is-active').css('display', 'flex').hide().fadeIn(150);

    $.post(sitecure_data.ajax_url, {
      action: 'sitecure_view_code',
      nonce: sitecure_data.nonce,
      finding_id: findingId
    }, function (res) {
      if (res.success) {
        var d = res.data;
        var isTrashed = (d.file_path && d.file_path.indexOf('[TRASHED]') !== -1) || (d.description && d.description.indexOf('[TRASHED]') !== -1);
        var cleanPath = (d.file_path || '').replace(/\[TRASHED\]/g, '').trim();

        if (isTrashed) {
          $('#wpd-code-modal-title').html(
            $('<div>').text(cleanPath + ' (Line: ' + d.line_number + ')').html() +
            ' <span class="wpd-badge" style="background:#fef2f2;color:#dc2626;border:1px solid #fca5a5;font-weight:700;font-size:11px;padding:2px 8px;border-radius:4px;margin-left:8px;vertical-align:middle;"><span class="dashicons dashicons-trash" style="font-size:13px;width:13px;height:13px;vertical-align:middle;"></span> IN TRASH</span>'
          );
        } else {
          $('#wpd-code-modal-title').text(cleanPath + ' (Line: ' + d.line_number + ')');
        }
        $('#wpd-code-modal-desc').text(d.description);

        if (d.evidence) {
          $('#wpd-code-modal-evidence-text').text(d.evidence);
          $('#wpd-code-modal-evidence-box').show();
        } else {
          $('#wpd-code-modal-evidence-box').hide();
        }

        var codeHtml = d.code_html;
        if (!codeHtml && d.code_snippet) {
          codeHtml = '<pre style="margin:0;padding:12px;font-family:monospace;white-space:pre-wrap;word-break:break-all;color:#e2e8f0;font-size:12px;line-height:1.5;">' + $('<div>').text(d.code_snippet).html() + '</pre>';
        } else if (!codeHtml) {
          codeHtml = '<div style="padding:20px;color:#94a3b8;text-align:center;">No direct code preview available for this item.</div>';
        }
        $('#wpd-code-modal-content').html(codeHtml);

        var actionsHtml = '';
        if (d.status === 'new' || d.status === 'restored') {
          var statusHtml = 'Status: <span class="wpd-tag wpd-tag-critical">ACTIVE THREAT</span>';
          if (isTrashed) {
            statusHtml += ' <span class="wpd-badge" style="background:#fef2f2;color:#dc2626;border:1px solid #fca5a5;font-weight:700;font-size:11px;padding:2px 8px;border-radius:4px;margin-left:6px;"><span class="dashicons dashicons-trash" style="font-size:13px;width:13px;height:13px;vertical-align:middle;"></span> IN TRASH</span>';
          }
          $('#wpd-code-modal-status-text').html(statusHtml);

          if (d.is_core || d.recommended_action === 'restore_core') {
            actionsHtml += '<button class="wpd-btn wpd-btn-primary wpd-btn-sm wpd-btn-repair-core" data-path="' + d.file_path + '"><span class="dashicons dashicons-update" style="font-size:14px;width:14px;height:14px;vertical-align:middle;"></span> Repair from WordPress.org</button>';
            actionsHtml += '<button class="wpd-btn wpd-btn-emergency wpd-btn-sm wpd-btn-quarantine" data-id="' + d.finding_id + '"><span class="dashicons dashicons-lock" style="font-size:14px;width:14px;height:14px;vertical-align:middle;"></span> Quarantine File</button>';
          } else if (d.category === 'seo_spam_injection') {
            actionsHtml += '<button class="wpd-btn wpd-btn-primary wpd-btn-sm wpd-btn-clean" data-id="' + d.finding_id + '"><span class="dashicons dashicons-shield-alt" style="font-size:14px;width:14px;height:14px;vertical-align:middle;"></span> Clean Spam from Page</button>';
            actionsHtml += '<button class="wpd-btn wpd-btn-emergency wpd-btn-sm wpd-btn-quarantine" data-id="' + d.finding_id + '"><span class="dashicons dashicons-lock" style="font-size:14px;width:14px;height:14px;vertical-align:middle;"></span> Quarantine Entire Page</button>';
          } else if (d.category === 'wpcode_snippet' || (d.file_path && d.file_path.indexOf('database:') === 0 && (d.category.indexOf('snippet') !== -1 || (d.evidence && d.evidence.indexOf('WPCode') !== -1)))) {
            actionsHtml += '<button class="wpd-btn wpd-btn-primary wpd-btn-sm wpd-btn-clean" data-id="' + d.finding_id + '"><span class="dashicons dashicons-shield-alt" style="font-size:14px;width:14px;height:14px;vertical-align:middle;"></span> Deactivate & Clean Snippet</button>';
            actionsHtml += '<button class="wpd-btn wpd-btn-emergency wpd-btn-sm wpd-btn-quarantine" data-id="' + d.finding_id + '"><span class="dashicons dashicons-lock" style="font-size:14px;width:14px;height:14px;vertical-align:middle;"></span> Quarantine & Delete Snippet</button>';
          } else if (d.file_path && d.file_path.indexOf('database:') === 0) {
            actionsHtml += '<button class="wpd-btn wpd-btn-primary wpd-btn-sm wpd-btn-clean" data-id="' + d.finding_id + '"><span class="dashicons dashicons-shield-alt" style="font-size:14px;width:14px;height:14px;vertical-align:middle;"></span> Clean Injected Record</button>';
            actionsHtml += '<button class="wpd-btn wpd-btn-emergency wpd-btn-sm wpd-btn-quarantine" data-id="' + d.finding_id + '"><span class="dashicons dashicons-lock" style="font-size:14px;width:14px;height:14px;vertical-align:middle;"></span> Quarantine & Remove from DB</button>';
          } else {
            actionsHtml += '<button class="wpd-btn wpd-btn-primary wpd-btn-sm wpd-btn-clean" data-id="' + d.finding_id + '"><span class="dashicons dashicons-shield-alt" style="font-size:14px;width:14px;height:14px;vertical-align:middle;"></span> Clean the File</button>';
            actionsHtml += '<button class="wpd-btn wpd-btn-emergency wpd-btn-sm wpd-btn-quarantine" data-id="' + d.finding_id + '"><span class="dashicons dashicons-lock" style="font-size:14px;width:14px;height:14px;vertical-align:middle;"></span> Quarantine & Remove File</button>';
          }
        } else {
          $('#wpd-code-modal-status-text').html('Status: <span class="wpd-tag wpd-tag-' + d.status + '">' + d.status.toUpperCase() + '</span>');
        }
        actionsHtml += '<button type="button" class="wpd-btn wpd-btn-secondary wpd-btn-sm" onclick="jQuery(\'#wpd-code-modal\').fadeOut(150, function() { jQuery(this).removeClass(\'is-active\'); });">Close</button>';
        $('#wpd-code-modal-actions').html(actionsHtml);

      } else {
        $('#wpd-code-modal-content').html('<div style="padding:20px;color:#f87171;">Failed to load code: ' + (res.data ? res.data.message : 'Error') + '</div>');
        $('#wpd-code-modal-actions').html('<button type="button" class="wpd-btn wpd-btn-secondary wpd-btn-sm" onclick="jQuery(\'#wpd-code-modal\').fadeOut(150, function() { jQuery(this).removeClass(\'is-active\'); });">Close</button>');
      }
    });
  }

})(jQuery);
