import { describe, it, expect } from 'vitest';
import { detectSecrets } from '../../src/leads/detectors/f1-secrets';

describe('Negative Corpus - Zero False Positives on Standard Libraries', () => {
  const JQUERY_SAMPLE = `
/*! jQuery v3.7.1 | (c) OpenJS Foundation and other contributors | jquery.org/license */
!function(e,t){"use strict";"object"==typeof module&&"object"==typeof module.exports?module.exports=e.document?t(e,!0):function(e){if(!e.document)throw new Error("jQuery requires a window with a document");return t(e)}:t(e)}("undefined"!=typeof window?window:this,function(C,e){"use strict";var t=[],r=Object.getPrototypeOf,s=t.slice,g=t.flat?function(e){return t.flat.call(e)}:function(e){return t.concat.apply([],e)};function S(e,t,n){var r,i,o=(t=t||E).createElement("script");if(o.text=e,n)for(r in w)(i=n[r]||n.getAttribute&&n.getAttribute(r))&&o.setAttribute(r,i);t.head.appendChild(o).parentNode.removeChild(o)}var E=C.document,k=/^[\\s\\uFEFF\\xA0]+|[\\s\\uFEFF\\xA0]+$/g;return C.jQuery=C.$=e;});
`;

  const REACT_SAMPLE = `
/** @license React v18.2.0
 * react.production.min.js
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * This source code is licensed under the MIT license found in the LICENSE file in the root directory of this source tree.
 */
!function(){"use strict";var e=Symbol.for("react.element"),t=Symbol.for("react.portal"),r=Symbol.for("react.fragment"),n=Symbol.for("react.strict_mode");function a(e,t,r){this.props=e,this.context=t,this.refs=emptyObject,this.updater=r||ReactNoopUpdateQueue}a.prototype.isReactComponent={};var o={isMounted:function(e){return!1},enqueueForceUpdate:function(e,t,r){},enqueueReplaceState:function(e,t,r){},enqueueSetState:function(e,t,r){}};var f=Object.assign;function c(e,t,r){this.props=e,this.context=t,this.refs=emptyObject,this.updater=r||ReactNoopUpdateQueue}c.prototype=new a;c.prototype.constructor=c;f(c.prototype,a.prototype);c.prototype.isPureReactComponent=!0;window.React={Component:a,PureComponent:c};}();
`;

  const LODASH_SAMPLE = `
/**
 * @license
 * Lodash <https://lodash.com/>
 * Copyright OpenJS Foundation and other contributors <https://openjsf.org/>
 * Released under MIT license <https://lodash.com/license>
 * Based on Underscore.js 1.8.3 <http://underscorejs.org/LICENSE>
 * Copyright Jeremy Ashkenas, DocumentCloud and Investigative Reporters & Editors
 */
;(function() {
  var undefined;
  var VERSION = '4.17.21';
  var HASH_UNDEFINED = '__lodash_hash_undefined__';
  var MAX_SAFE_INTEGER = 9007199254740991;
  var reIsDeepProp = /\\.|(?:\\[(?:[^\\]]*)\\])/;
  function lodash(value) { return value; }
  lodash.VERSION = VERSION;
  if (typeof exports == 'object' && exports && !exports.nodeType) { module.exports = lodash; }
}).call(this);
`;

  it('scans jQuery and yields zero secret leads', () => {
    const leads = detectSecrets(JQUERY_SAMPLE, 'https://example.com/jquery.js', 'in-scope');
    const secretLeads = leads.filter(l => l.ruleId.startsWith('SEC-') && l.potential !== 'info');
    expect(secretLeads).toHaveLength(0);
  });

  it('scans React production bundle and yields zero secret leads', () => {
    const leads = detectSecrets(REACT_SAMPLE, 'https://example.com/react.js', 'in-scope');
    const secretLeads = leads.filter(l => l.ruleId.startsWith('SEC-') && l.potential !== 'info');
    expect(secretLeads).toHaveLength(0);
  });

  it('scans Lodash bundle and yields zero secret leads', () => {
    const leads = detectSecrets(LODASH_SAMPLE, 'https://example.com/lodash.js', 'in-scope');
    const secretLeads = leads.filter(l => l.ruleId.startsWith('SEC-') && l.potential !== 'info');
    expect(secretLeads).toHaveLength(0);
  });
});
