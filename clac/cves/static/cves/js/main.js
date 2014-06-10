/* global $ */

function init_cve_annotation() {
  'use strict';

  $( '.cve-annotation .explanation' ).hide();
  $( '#annotation_memory_safety_vulnerability .explanation' ).show();
  $( '#annotation_memory_safety_vulnerability select' ).focus();

  $( '#annotation_always_crash' ).hide();
  $( '#annotation_memory_access' ).hide();
  $( '#annotation_control_flow_vulnerability' ).hide();
  $( '#annotation_undefined_behavior_vulnerability' ).hide();
  $( '#annotation_approximate_spatial_safety' ).hide();
  $( '#annotation_approximate_temporal_safety' ).hide();

  $( '#annotation_memory_safety_vulnerability select' ).change(function() {
    var value = $( '#annotation_memory_safety_vulnerability select' ).val();
    if (value !== '') {
      $( '#annotation_memory_safety_vulnerability .explanation' ).hide();
    }

    if (value === 'YES') {
      $( '#annotation_always_crash' ).show('fast');
      $( '#annotation_always_crash .explanation' ).show();
      $( '#annotation_always_crash select' ).focus();
      $( '#annotation_memory_access' ).show('fast');
      $( '#annotation_control_flow_vulnerability' ).show('fast');
      $( '#annotation_approximate_spatial_safety' ).show('fast');
      $( '#annotation_approximate_temporal_safety' ).show('fast');
    } else if (value === 'NO') {
      $( '#annotation_undefined_behavior_vulnerability' ).show('fast');
      $( '#annotation_undefined_behavior_vulnerability .explanation' ).show();
      $( '#annotation_undefined_behavior_vulnerability select' ).focus();
    } else if (value === 'UNKNOWN') {
      $( '#submit_annotation' ).focus();
    }
  });

  $( '#annotation_always_crash select' ).change(function() {
    var value = $( '#annotation_always_crash select' ).val();
    if (value !== '') {
      $( '#annotation_always_crash .explanation' ).hide();
      $( '#annotation_memory_access' ).show('fast');
      $( '#annotation_memory_access .explanation' ).show();
      $( '#annotation_memory_access select' ).focus();
    }
  });

  $( '#annotation_memory_access select' ).change(function() {
    var value = $( '#annotation_memory_access select' ).val();
    if (value !== '') {
      $( '#annotation_memory_access .explanation' ).hide();
      $( '#annotation_control_flow_vulnerability .explanation' ).show('fast');
      $( '#annotation_control_flow_vulnerability select' ).focus();
    }

    if (value === 'READ') {
      $( '#annotation_control_flow_vulnerability select' ).val('NO');
      $( '#annotation_control_flow_vulnerability select' ).change();
    }
  });

  $( '#annotation_control_flow_vulnerability select' ).change(function() {
    var value = $( '#annotation_control_flow_vulnerability select' ).val();
    if (value !== '') {
      $( '#annotation_control_flow_vulnerability .explanation' ).hide();
      $( '#annotation_approximate_spatial_safety .explanation' ).show('fast');
      $( '#annotation_approximate_spatial_safety select' ).focus();
    }
  });

  $( '#annotation_approximate_spatial_safety select' ).change(function() {
    var value = $( '#annotation_approximate_spatial_safety select' ).val();
    if (value !== '') {
      $( '#annotation_approximate_spatial_safety .explanation' ).hide();
      $( '#annotation_approximate_temporal_safety .explanation' ).show('fast');
      $( '#annotation_approximate_temporal_safety select' ).focus();
    }
  });

  $( '#annotation_approximate_temporal_safety select' ).change(function() {
    var value = $( '#annotation_approximate_temporal_safety select' ).val();
    if (value !== '') {
      $( '#annotation_approximate_temporal_safety .explanation' ).hide();
      $( '#submit_annotation' ).focus();
    }
  });

  $( '#annotation_undefined_behavior_vulnerability select' ).change(function() {
    var value = $( '#annotation_undefined_behavior_vulnerability select' ).val();
    if (value !== '') {
      $( '#annotation_undefined_behavior_vulnerability .explanation' ).hide();
      $( '#submit_annotation' ).focus();
    }
  });
}
