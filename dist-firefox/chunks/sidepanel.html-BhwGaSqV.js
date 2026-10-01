import { p as SIDEPANEL_PORT_NAME, r as sendToBackground } from "./messaging-BCRf7spF.js";
import { n as registrableDomain } from "./subdomain-trust-B3Jbs8TC.js";
import "./modulepreload-polyfill-BsPm7yBB.js";
//#region node_modules/d3-force/src/center.js
function center_default(x, y) {
	var nodes, strength = 1;
	if (x == null) x = 0;
	if (y == null) y = 0;
	function force() {
		var i, n = nodes.length, node, sx = 0, sy = 0;
		for (i = 0; i < n; ++i) node = nodes[i], sx += node.x, sy += node.y;
		for (sx = (sx / n - x) * strength, sy = (sy / n - y) * strength, i = 0; i < n; ++i) node = nodes[i], node.x -= sx, node.y -= sy;
	}
	force.initialize = function(_) {
		nodes = _;
	};
	force.x = function(_) {
		return arguments.length ? (x = +_, force) : x;
	};
	force.y = function(_) {
		return arguments.length ? (y = +_, force) : y;
	};
	force.strength = function(_) {
		return arguments.length ? (strength = +_, force) : strength;
	};
	return force;
}
//#endregion
//#region node_modules/d3-quadtree/src/add.js
function add_default(d) {
	const x = +this._x.call(null, d), y = +this._y.call(null, d);
	return add(this.cover(x, y), x, y, d);
}
function add(tree, x, y, d) {
	if (isNaN(x) || isNaN(y)) return tree;
	var parent, node = tree._root, leaf = { data: d }, x0 = tree._x0, y0 = tree._y0, x1 = tree._x1, y1 = tree._y1, xm, ym, xp, yp, right, bottom, i, j;
	if (!node) return tree._root = leaf, tree;
	while (node.length) {
		if (right = x >= (xm = (x0 + x1) / 2)) x0 = xm;
		else x1 = xm;
		if (bottom = y >= (ym = (y0 + y1) / 2)) y0 = ym;
		else y1 = ym;
		if (parent = node, !(node = node[i = bottom << 1 | right])) return parent[i] = leaf, tree;
	}
	xp = +tree._x.call(null, node.data);
	yp = +tree._y.call(null, node.data);
	if (x === xp && y === yp) return leaf.next = node, parent ? parent[i] = leaf : tree._root = leaf, tree;
	do {
		parent = parent ? parent[i] = new Array(4) : tree._root = new Array(4);
		if (right = x >= (xm = (x0 + x1) / 2)) x0 = xm;
		else x1 = xm;
		if (bottom = y >= (ym = (y0 + y1) / 2)) y0 = ym;
		else y1 = ym;
	} while ((i = bottom << 1 | right) === (j = (yp >= ym) << 1 | xp >= xm));
	return parent[j] = node, parent[i] = leaf, tree;
}
function addAll(data) {
	var d, i, n = data.length, x, y, xz = new Array(n), yz = new Array(n), x0 = Infinity, y0 = Infinity, x1 = -Infinity, y1 = -Infinity;
	for (i = 0; i < n; ++i) {
		if (isNaN(x = +this._x.call(null, d = data[i])) || isNaN(y = +this._y.call(null, d))) continue;
		xz[i] = x;
		yz[i] = y;
		if (x < x0) x0 = x;
		if (x > x1) x1 = x;
		if (y < y0) y0 = y;
		if (y > y1) y1 = y;
	}
	if (x0 > x1 || y0 > y1) return this;
	this.cover(x0, y0).cover(x1, y1);
	for (i = 0; i < n; ++i) add(this, xz[i], yz[i], data[i]);
	return this;
}
//#endregion
//#region node_modules/d3-quadtree/src/cover.js
function cover_default(x, y) {
	if (isNaN(x = +x) || isNaN(y = +y)) return this;
	var x0 = this._x0, y0 = this._y0, x1 = this._x1, y1 = this._y1;
	if (isNaN(x0)) {
		x1 = (x0 = Math.floor(x)) + 1;
		y1 = (y0 = Math.floor(y)) + 1;
	} else {
		var z = x1 - x0 || 1, node = this._root, parent, i;
		while (x0 > x || x >= x1 || y0 > y || y >= y1) {
			i = (y < y0) << 1 | x < x0;
			parent = new Array(4), parent[i] = node, node = parent, z *= 2;
			switch (i) {
				case 0:
					x1 = x0 + z, y1 = y0 + z;
					break;
				case 1:
					x0 = x1 - z, y1 = y0 + z;
					break;
				case 2:
					x1 = x0 + z, y0 = y1 - z;
					break;
				case 3: x0 = x1 - z, y0 = y1 - z;
			}
		}
		if (this._root && this._root.length) this._root = node;
	}
	this._x0 = x0;
	this._y0 = y0;
	this._x1 = x1;
	this._y1 = y1;
	return this;
}
//#endregion
//#region node_modules/d3-quadtree/src/data.js
function data_default() {
	var data = [];
	this.visit(function(node) {
		if (!node.length) do
			data.push(node.data);
		while (node = node.next);
	});
	return data;
}
//#endregion
//#region node_modules/d3-quadtree/src/extent.js
function extent_default(_) {
	return arguments.length ? this.cover(+_[0][0], +_[0][1]).cover(+_[1][0], +_[1][1]) : isNaN(this._x0) ? void 0 : [[this._x0, this._y0], [this._x1, this._y1]];
}
//#endregion
//#region node_modules/d3-quadtree/src/quad.js
function quad_default(node, x0, y0, x1, y1) {
	this.node = node;
	this.x0 = x0;
	this.y0 = y0;
	this.x1 = x1;
	this.y1 = y1;
}
//#endregion
//#region node_modules/d3-quadtree/src/find.js
function find_default(x, y, radius) {
	var data, x0 = this._x0, y0 = this._y0, x1, y1, x2, y2, x3 = this._x1, y3 = this._y1, quads = [], node = this._root, q, i;
	if (node) quads.push(new quad_default(node, x0, y0, x3, y3));
	if (radius == null) radius = Infinity;
	else {
		x0 = x - radius, y0 = y - radius;
		x3 = x + radius, y3 = y + radius;
		radius *= radius;
	}
	while (q = quads.pop()) {
		if (!(node = q.node) || (x1 = q.x0) > x3 || (y1 = q.y0) > y3 || (x2 = q.x1) < x0 || (y2 = q.y1) < y0) continue;
		if (node.length) {
			var xm = (x1 + x2) / 2, ym = (y1 + y2) / 2;
			quads.push(new quad_default(node[3], xm, ym, x2, y2), new quad_default(node[2], x1, ym, xm, y2), new quad_default(node[1], xm, y1, x2, ym), new quad_default(node[0], x1, y1, xm, ym));
			if (i = (y >= ym) << 1 | x >= xm) {
				q = quads[quads.length - 1];
				quads[quads.length - 1] = quads[quads.length - 1 - i];
				quads[quads.length - 1 - i] = q;
			}
		} else {
			var dx = x - +this._x.call(null, node.data), dy = y - +this._y.call(null, node.data), d2 = dx * dx + dy * dy;
			if (d2 < radius) {
				var d = Math.sqrt(radius = d2);
				x0 = x - d, y0 = y - d;
				x3 = x + d, y3 = y + d;
				data = node.data;
			}
		}
	}
	return data;
}
//#endregion
//#region node_modules/d3-quadtree/src/remove.js
function remove_default(d) {
	if (isNaN(x = +this._x.call(null, d)) || isNaN(y = +this._y.call(null, d))) return this;
	var parent, node = this._root, retainer, previous, next, x0 = this._x0, y0 = this._y0, x1 = this._x1, y1 = this._y1, x, y, xm, ym, right, bottom, i, j;
	if (!node) return this;
	if (node.length) while (true) {
		if (right = x >= (xm = (x0 + x1) / 2)) x0 = xm;
		else x1 = xm;
		if (bottom = y >= (ym = (y0 + y1) / 2)) y0 = ym;
		else y1 = ym;
		if (!(parent = node, node = node[i = bottom << 1 | right])) return this;
		if (!node.length) break;
		if (parent[i + 1 & 3] || parent[i + 2 & 3] || parent[i + 3 & 3]) retainer = parent, j = i;
	}
	while (node.data !== d) if (!(previous = node, node = node.next)) return this;
	if (next = node.next) delete node.next;
	if (previous) return next ? previous.next = next : delete previous.next, this;
	if (!parent) return this._root = next, this;
	next ? parent[i] = next : delete parent[i];
	if ((node = parent[0] || parent[1] || parent[2] || parent[3]) && node === (parent[3] || parent[2] || parent[1] || parent[0]) && !node.length) {
		if (retainer) retainer[j] = node;
		else this._root = node;
	}
	return this;
}
function removeAll(data) {
	for (var i = 0, n = data.length; i < n; ++i) this.remove(data[i]);
	return this;
}
//#endregion
//#region node_modules/d3-quadtree/src/root.js
function root_default() {
	return this._root;
}
//#endregion
//#region node_modules/d3-quadtree/src/size.js
function size_default() {
	var size = 0;
	this.visit(function(node) {
		if (!node.length) do
			++size;
		while (node = node.next);
	});
	return size;
}
//#endregion
//#region node_modules/d3-quadtree/src/visit.js
function visit_default(callback) {
	var quads = [], q, node = this._root, child, x0, y0, x1, y1;
	if (node) quads.push(new quad_default(node, this._x0, this._y0, this._x1, this._y1));
	while (q = quads.pop()) if (!callback(node = q.node, x0 = q.x0, y0 = q.y0, x1 = q.x1, y1 = q.y1) && node.length) {
		var xm = (x0 + x1) / 2, ym = (y0 + y1) / 2;
		if (child = node[3]) quads.push(new quad_default(child, xm, ym, x1, y1));
		if (child = node[2]) quads.push(new quad_default(child, x0, ym, xm, y1));
		if (child = node[1]) quads.push(new quad_default(child, xm, y0, x1, ym));
		if (child = node[0]) quads.push(new quad_default(child, x0, y0, xm, ym));
	}
	return this;
}
//#endregion
//#region node_modules/d3-quadtree/src/visitAfter.js
function visitAfter_default(callback) {
	var quads = [], next = [], q;
	if (this._root) quads.push(new quad_default(this._root, this._x0, this._y0, this._x1, this._y1));
	while (q = quads.pop()) {
		var node = q.node;
		if (node.length) {
			var child, x0 = q.x0, y0 = q.y0, x1 = q.x1, y1 = q.y1, xm = (x0 + x1) / 2, ym = (y0 + y1) / 2;
			if (child = node[0]) quads.push(new quad_default(child, x0, y0, xm, ym));
			if (child = node[1]) quads.push(new quad_default(child, xm, y0, x1, ym));
			if (child = node[2]) quads.push(new quad_default(child, x0, ym, xm, y1));
			if (child = node[3]) quads.push(new quad_default(child, xm, ym, x1, y1));
		}
		next.push(q);
	}
	while (q = next.pop()) callback(q.node, q.x0, q.y0, q.x1, q.y1);
	return this;
}
//#endregion
//#region node_modules/d3-quadtree/src/x.js
function defaultX(d) {
	return d[0];
}
function x_default(_) {
	return arguments.length ? (this._x = _, this) : this._x;
}
//#endregion
//#region node_modules/d3-quadtree/src/y.js
function defaultY(d) {
	return d[1];
}
function y_default(_) {
	return arguments.length ? (this._y = _, this) : this._y;
}
//#endregion
//#region node_modules/d3-quadtree/src/quadtree.js
function quadtree(nodes, x, y) {
	var tree = new Quadtree(x == null ? defaultX : x, y == null ? defaultY : y, NaN, NaN, NaN, NaN);
	return nodes == null ? tree : tree.addAll(nodes);
}
function Quadtree(x, y, x0, y0, x1, y1) {
	this._x = x;
	this._y = y;
	this._x0 = x0;
	this._y0 = y0;
	this._x1 = x1;
	this._y1 = y1;
	this._root = void 0;
}
function leaf_copy(leaf) {
	var copy = { data: leaf.data }, next = copy;
	while (leaf = leaf.next) next = next.next = { data: leaf.data };
	return copy;
}
var treeProto = quadtree.prototype = Quadtree.prototype;
treeProto.copy = function() {
	var copy = new Quadtree(this._x, this._y, this._x0, this._y0, this._x1, this._y1), node = this._root, nodes, child;
	if (!node) return copy;
	if (!node.length) return copy._root = leaf_copy(node), copy;
	nodes = [{
		source: node,
		target: copy._root = new Array(4)
	}];
	while (node = nodes.pop()) for (var i = 0; i < 4; ++i) if (child = node.source[i]) {
		if (child.length) nodes.push({
			source: child,
			target: node.target[i] = new Array(4)
		});
		else node.target[i] = leaf_copy(child);
	}
	return copy;
};
treeProto.add = add_default;
treeProto.addAll = addAll;
treeProto.cover = cover_default;
treeProto.data = data_default;
treeProto.extent = extent_default;
treeProto.find = find_default;
treeProto.remove = remove_default;
treeProto.removeAll = removeAll;
treeProto.root = root_default;
treeProto.size = size_default;
treeProto.visit = visit_default;
treeProto.visitAfter = visitAfter_default;
treeProto.x = x_default;
treeProto.y = y_default;
//#endregion
//#region node_modules/d3-force/src/constant.js
function constant_default(x) {
	return function() {
		return x;
	};
}
//#endregion
//#region node_modules/d3-force/src/jiggle.js
function jiggle_default(random) {
	return (random() - .5) * 1e-6;
}
//#endregion
//#region node_modules/d3-force/src/collide.js
function x$1(d) {
	return d.x + d.vx;
}
function y$1(d) {
	return d.y + d.vy;
}
function collide_default(radius) {
	var nodes, radii, random, strength = 1, iterations = 1;
	if (typeof radius !== "function") radius = constant_default(radius == null ? 1 : +radius);
	function force() {
		var i, n = nodes.length, tree, node, xi, yi, ri, ri2;
		for (var k = 0; k < iterations; ++k) {
			tree = quadtree(nodes, x$1, y$1).visitAfter(prepare);
			for (i = 0; i < n; ++i) {
				node = nodes[i];
				ri = radii[node.index], ri2 = ri * ri;
				xi = node.x + node.vx;
				yi = node.y + node.vy;
				tree.visit(apply);
			}
		}
		function apply(quad, x0, y0, x1, y1) {
			var data = quad.data, rj = quad.r, r = ri + rj;
			if (data) {
				if (data.index > node.index) {
					var x = xi - data.x - data.vx, y = yi - data.y - data.vy, l = x * x + y * y;
					if (l < r * r) {
						if (x === 0) x = jiggle_default(random), l += x * x;
						if (y === 0) y = jiggle_default(random), l += y * y;
						l = (r - (l = Math.sqrt(l))) / l * strength;
						node.vx += (x *= l) * (r = (rj *= rj) / (ri2 + rj));
						node.vy += (y *= l) * r;
						data.vx -= x * (r = 1 - r);
						data.vy -= y * r;
					}
				}
				return;
			}
			return x0 > xi + r || x1 < xi - r || y0 > yi + r || y1 < yi - r;
		}
	}
	function prepare(quad) {
		if (quad.data) return quad.r = radii[quad.data.index];
		for (var i = quad.r = 0; i < 4; ++i) if (quad[i] && quad[i].r > quad.r) quad.r = quad[i].r;
	}
	function initialize() {
		if (!nodes) return;
		var i, n = nodes.length, node;
		radii = new Array(n);
		for (i = 0; i < n; ++i) node = nodes[i], radii[node.index] = +radius(node, i, nodes);
	}
	force.initialize = function(_nodes, _random) {
		nodes = _nodes;
		random = _random;
		initialize();
	};
	force.iterations = function(_) {
		return arguments.length ? (iterations = +_, force) : iterations;
	};
	force.strength = function(_) {
		return arguments.length ? (strength = +_, force) : strength;
	};
	force.radius = function(_) {
		return arguments.length ? (radius = typeof _ === "function" ? _ : constant_default(+_), initialize(), force) : radius;
	};
	return force;
}
//#endregion
//#region node_modules/d3-force/src/link.js
function index(d) {
	return d.index;
}
function find(nodeById, nodeId) {
	var node = nodeById.get(nodeId);
	if (!node) throw new Error("node not found: " + nodeId);
	return node;
}
function link_default(links) {
	var id = index, strength = defaultStrength, strengths, distance = constant_default(30), distances, nodes, count, bias, random, iterations = 1;
	if (links == null) links = [];
	function defaultStrength(link) {
		return 1 / Math.min(count[link.source.index], count[link.target.index]);
	}
	function force(alpha) {
		for (var k = 0, n = links.length; k < iterations; ++k) for (var i = 0, link, source, target, x, y, l, b; i < n; ++i) {
			link = links[i], source = link.source, target = link.target;
			x = target.x + target.vx - source.x - source.vx || jiggle_default(random);
			y = target.y + target.vy - source.y - source.vy || jiggle_default(random);
			l = Math.sqrt(x * x + y * y);
			l = (l - distances[i]) / l * alpha * strengths[i];
			x *= l, y *= l;
			target.vx -= x * (b = bias[i]);
			target.vy -= y * b;
			source.vx += x * (b = 1 - b);
			source.vy += y * b;
		}
	}
	function initialize() {
		if (!nodes) return;
		var i, n = nodes.length, m = links.length, nodeById = new Map(nodes.map((d, i) => [id(d, i, nodes), d])), link;
		for (i = 0, count = new Array(n); i < m; ++i) {
			link = links[i], link.index = i;
			if (typeof link.source !== "object") link.source = find(nodeById, link.source);
			if (typeof link.target !== "object") link.target = find(nodeById, link.target);
			count[link.source.index] = (count[link.source.index] || 0) + 1;
			count[link.target.index] = (count[link.target.index] || 0) + 1;
		}
		for (i = 0, bias = new Array(m); i < m; ++i) link = links[i], bias[i] = count[link.source.index] / (count[link.source.index] + count[link.target.index]);
		strengths = new Array(m), initializeStrength();
		distances = new Array(m), initializeDistance();
	}
	function initializeStrength() {
		if (!nodes) return;
		for (var i = 0, n = links.length; i < n; ++i) strengths[i] = +strength(links[i], i, links);
	}
	function initializeDistance() {
		if (!nodes) return;
		for (var i = 0, n = links.length; i < n; ++i) distances[i] = +distance(links[i], i, links);
	}
	force.initialize = function(_nodes, _random) {
		nodes = _nodes;
		random = _random;
		initialize();
	};
	force.links = function(_) {
		return arguments.length ? (links = _, initialize(), force) : links;
	};
	force.id = function(_) {
		return arguments.length ? (id = _, force) : id;
	};
	force.iterations = function(_) {
		return arguments.length ? (iterations = +_, force) : iterations;
	};
	force.strength = function(_) {
		return arguments.length ? (strength = typeof _ === "function" ? _ : constant_default(+_), initializeStrength(), force) : strength;
	};
	force.distance = function(_) {
		return arguments.length ? (distance = typeof _ === "function" ? _ : constant_default(+_), initializeDistance(), force) : distance;
	};
	return force;
}
//#endregion
//#region node_modules/d3-dispatch/src/dispatch.js
var noop = { value: () => {} };
function dispatch() {
	for (var i = 0, n = arguments.length, _ = {}, t; i < n; ++i) {
		if (!(t = arguments[i] + "") || t in _ || /[\s.]/.test(t)) throw new Error("illegal type: " + t);
		_[t] = [];
	}
	return new Dispatch(_);
}
function Dispatch(_) {
	this._ = _;
}
function parseTypenames(typenames, types) {
	return typenames.trim().split(/^|\s+/).map(function(t) {
		var name = "", i = t.indexOf(".");
		if (i >= 0) name = t.slice(i + 1), t = t.slice(0, i);
		if (t && !types.hasOwnProperty(t)) throw new Error("unknown type: " + t);
		return {
			type: t,
			name
		};
	});
}
Dispatch.prototype = dispatch.prototype = {
	constructor: Dispatch,
	on: function(typename, callback) {
		var _ = this._, T = parseTypenames(typename + "", _), t, i = -1, n = T.length;
		if (arguments.length < 2) {
			while (++i < n) if ((t = (typename = T[i]).type) && (t = get(_[t], typename.name))) return t;
			return;
		}
		if (callback != null && typeof callback !== "function") throw new Error("invalid callback: " + callback);
		while (++i < n) if (t = (typename = T[i]).type) _[t] = set(_[t], typename.name, callback);
		else if (callback == null) for (t in _) _[t] = set(_[t], typename.name, null);
		return this;
	},
	copy: function() {
		var copy = {}, _ = this._;
		for (var t in _) copy[t] = _[t].slice();
		return new Dispatch(copy);
	},
	call: function(type, that) {
		if ((n = arguments.length - 2) > 0) for (var args = new Array(n), i = 0, n, t; i < n; ++i) args[i] = arguments[i + 2];
		if (!this._.hasOwnProperty(type)) throw new Error("unknown type: " + type);
		for (t = this._[type], i = 0, n = t.length; i < n; ++i) t[i].value.apply(that, args);
	},
	apply: function(type, that, args) {
		if (!this._.hasOwnProperty(type)) throw new Error("unknown type: " + type);
		for (var t = this._[type], i = 0, n = t.length; i < n; ++i) t[i].value.apply(that, args);
	}
};
function get(type, name) {
	for (var i = 0, n = type.length, c; i < n; ++i) if ((c = type[i]).name === name) return c.value;
}
function set(type, name, callback) {
	for (var i = 0, n = type.length; i < n; ++i) if (type[i].name === name) {
		type[i] = noop, type = type.slice(0, i).concat(type.slice(i + 1));
		break;
	}
	if (callback != null) type.push({
		name,
		value: callback
	});
	return type;
}
//#endregion
//#region node_modules/d3-timer/src/timer.js
var frame = 0;
var timeout = 0;
var interval = 0;
var pokeDelay = 1e3;
var taskHead;
var taskTail;
var clockLast = 0;
var clockNow = 0;
var clockSkew = 0;
var clock = typeof performance === "object" && performance.now ? performance : Date;
var setFrame = typeof window === "object" && window.requestAnimationFrame ? window.requestAnimationFrame.bind(window) : function(f) {
	setTimeout(f, 17);
};
function now() {
	return clockNow || (setFrame(clearNow), clockNow = clock.now() + clockSkew);
}
function clearNow() {
	clockNow = 0;
}
function Timer() {
	this._call = this._time = this._next = null;
}
Timer.prototype = timer.prototype = {
	constructor: Timer,
	restart: function(callback, delay, time) {
		if (typeof callback !== "function") throw new TypeError("callback is not a function");
		time = (time == null ? now() : +time) + (delay == null ? 0 : +delay);
		if (!this._next && taskTail !== this) {
			if (taskTail) taskTail._next = this;
			else taskHead = this;
			taskTail = this;
		}
		this._call = callback;
		this._time = time;
		sleep();
	},
	stop: function() {
		if (this._call) {
			this._call = null;
			this._time = Infinity;
			sleep();
		}
	}
};
function timer(callback, delay, time) {
	var t = new Timer();
	t.restart(callback, delay, time);
	return t;
}
function timerFlush() {
	now();
	++frame;
	var t = taskHead, e;
	while (t) {
		if ((e = clockNow - t._time) >= 0) t._call.call(void 0, e);
		t = t._next;
	}
	--frame;
}
function wake() {
	clockNow = (clockLast = clock.now()) + clockSkew;
	frame = timeout = 0;
	try {
		timerFlush();
	} finally {
		frame = 0;
		nap();
		clockNow = 0;
	}
}
function poke() {
	var now = clock.now(), delay = now - clockLast;
	if (delay > pokeDelay) clockSkew -= delay, clockLast = now;
}
function nap() {
	var t0, t1 = taskHead, t2, time = Infinity;
	while (t1) if (t1._call) {
		if (time > t1._time) time = t1._time;
		t0 = t1, t1 = t1._next;
	} else {
		t2 = t1._next, t1._next = null;
		t1 = t0 ? t0._next = t2 : taskHead = t2;
	}
	taskTail = t0;
	sleep(time);
}
function sleep(time) {
	if (frame) return;
	if (timeout) timeout = clearTimeout(timeout);
	if (time - clockNow > 24) {
		if (time < Infinity) timeout = setTimeout(wake, time - clock.now() - clockSkew);
		if (interval) interval = clearInterval(interval);
	} else {
		if (!interval) clockLast = clock.now(), interval = setInterval(poke, pokeDelay);
		frame = 1, setFrame(wake);
	}
}
//#endregion
//#region node_modules/d3-force/src/lcg.js
var a = 1664525;
var c = 1013904223;
var m = 4294967296;
function lcg_default() {
	let s = 1;
	return () => (s = (a * s + c) % m) / m;
}
//#endregion
//#region node_modules/d3-force/src/simulation.js
function x(d) {
	return d.x;
}
function y(d) {
	return d.y;
}
var initialRadius = 10;
var initialAngle = Math.PI * (3 - Math.sqrt(5));
function simulation_default(nodes) {
	var simulation, alpha = 1, alphaMin = .001, alphaDecay = 1 - Math.pow(alphaMin, 1 / 300), alphaTarget = 0, velocityDecay = .6, forces = /* @__PURE__ */ new Map(), stepper = timer(step), event = dispatch("tick", "end"), random = lcg_default();
	if (nodes == null) nodes = [];
	function step() {
		tick();
		event.call("tick", simulation);
		if (alpha < alphaMin) {
			stepper.stop();
			event.call("end", simulation);
		}
	}
	function tick(iterations) {
		var i, n = nodes.length, node;
		if (iterations === void 0) iterations = 1;
		for (var k = 0; k < iterations; ++k) {
			alpha += (alphaTarget - alpha) * alphaDecay;
			forces.forEach(function(force) {
				force(alpha);
			});
			for (i = 0; i < n; ++i) {
				node = nodes[i];
				if (node.fx == null) node.x += node.vx *= velocityDecay;
				else node.x = node.fx, node.vx = 0;
				if (node.fy == null) node.y += node.vy *= velocityDecay;
				else node.y = node.fy, node.vy = 0;
			}
		}
		return simulation;
	}
	function initializeNodes() {
		for (var i = 0, n = nodes.length, node; i < n; ++i) {
			node = nodes[i], node.index = i;
			if (node.fx != null) node.x = node.fx;
			if (node.fy != null) node.y = node.fy;
			if (isNaN(node.x) || isNaN(node.y)) {
				var radius = initialRadius * Math.sqrt(.5 + i), angle = i * initialAngle;
				node.x = radius * Math.cos(angle);
				node.y = radius * Math.sin(angle);
			}
			if (isNaN(node.vx) || isNaN(node.vy)) node.vx = node.vy = 0;
		}
	}
	function initializeForce(force) {
		if (force.initialize) force.initialize(nodes, random);
		return force;
	}
	initializeNodes();
	return simulation = {
		tick,
		restart: function() {
			return stepper.restart(step), simulation;
		},
		stop: function() {
			return stepper.stop(), simulation;
		},
		nodes: function(_) {
			return arguments.length ? (nodes = _, initializeNodes(), forces.forEach(initializeForce), simulation) : nodes;
		},
		alpha: function(_) {
			return arguments.length ? (alpha = +_, simulation) : alpha;
		},
		alphaMin: function(_) {
			return arguments.length ? (alphaMin = +_, simulation) : alphaMin;
		},
		alphaDecay: function(_) {
			return arguments.length ? (alphaDecay = +_, simulation) : +alphaDecay;
		},
		alphaTarget: function(_) {
			return arguments.length ? (alphaTarget = +_, simulation) : alphaTarget;
		},
		velocityDecay: function(_) {
			return arguments.length ? (velocityDecay = 1 - _, simulation) : 1 - velocityDecay;
		},
		randomSource: function(_) {
			return arguments.length ? (random = _, forces.forEach(initializeForce), simulation) : random;
		},
		force: function(name, _) {
			return arguments.length > 1 ? (_ == null ? forces.delete(name) : forces.set(name, initializeForce(_)), simulation) : forces.get(name);
		},
		find: function(x, y, radius) {
			var i = 0, n = nodes.length, dx, dy, d2, node, closest;
			if (radius == null) radius = Infinity;
			else radius *= radius;
			for (i = 0; i < n; ++i) {
				node = nodes[i];
				dx = x - node.x;
				dy = y - node.y;
				d2 = dx * dx + dy * dy;
				if (d2 < radius) closest = node, radius = d2;
			}
			return closest;
		},
		on: function(name, _) {
			return arguments.length > 1 ? (event.on(name, _), simulation) : event.on(name);
		}
	};
}
//#endregion
//#region node_modules/d3-force/src/manyBody.js
function manyBody_default() {
	var nodes, node, random, alpha, strength = constant_default(-30), strengths, distanceMin2 = 1, distanceMax2 = Infinity, theta2 = .81;
	function force(_) {
		var i, n = nodes.length, tree = quadtree(nodes, x, y).visitAfter(accumulate);
		for (alpha = _, i = 0; i < n; ++i) node = nodes[i], tree.visit(apply);
	}
	function initialize() {
		if (!nodes) return;
		var i, n = nodes.length, node;
		strengths = new Array(n);
		for (i = 0; i < n; ++i) node = nodes[i], strengths[node.index] = +strength(node, i, nodes);
	}
	function accumulate(quad) {
		var strength = 0, q, c, weight = 0, x, y, i;
		if (quad.length) {
			for (x = y = i = 0; i < 4; ++i) if ((q = quad[i]) && (c = Math.abs(q.value))) strength += q.value, weight += c, x += c * q.x, y += c * q.y;
			quad.x = x / weight;
			quad.y = y / weight;
		} else {
			q = quad;
			q.x = q.data.x;
			q.y = q.data.y;
			do
				strength += strengths[q.data.index];
			while (q = q.next);
		}
		quad.value = strength;
	}
	function apply(quad, x1, _, x2) {
		if (!quad.value) return true;
		var x = quad.x - node.x, y = quad.y - node.y, w = x2 - x1, l = x * x + y * y;
		if (w * w / theta2 < l) {
			if (l < distanceMax2) {
				if (x === 0) x = jiggle_default(random), l += x * x;
				if (y === 0) y = jiggle_default(random), l += y * y;
				if (l < distanceMin2) l = Math.sqrt(distanceMin2 * l);
				node.vx += x * quad.value * alpha / l;
				node.vy += y * quad.value * alpha / l;
			}
			return true;
		} else if (quad.length || l >= distanceMax2) return;
		if (quad.data !== node || quad.next) {
			if (x === 0) x = jiggle_default(random), l += x * x;
			if (y === 0) y = jiggle_default(random), l += y * y;
			if (l < distanceMin2) l = Math.sqrt(distanceMin2 * l);
		}
		do
			if (quad.data !== node) {
				w = strengths[quad.data.index] * alpha / l;
				node.vx += x * w;
				node.vy += y * w;
			}
		while (quad = quad.next);
	}
	force.initialize = function(_nodes, _random) {
		nodes = _nodes;
		random = _random;
		initialize();
	};
	force.strength = function(_) {
		return arguments.length ? (strength = typeof _ === "function" ? _ : constant_default(+_), initialize(), force) : strength;
	};
	force.distanceMin = function(_) {
		return arguments.length ? (distanceMin2 = _ * _, force) : Math.sqrt(distanceMin2);
	};
	force.distanceMax = function(_) {
		return arguments.length ? (distanceMax2 = _ * _, force) : Math.sqrt(distanceMax2);
	};
	force.theta = function(_) {
		return arguments.length ? (theta2 = _ * _, force) : Math.sqrt(theta2);
	};
	return force;
}
//#endregion
//#region src/sidepanel/sidepanel.ts
/**
* sidepanel.ts — Attack Surface Graph visualization using d3-force and SVG DOM.
*
* Rules:
*  - ZERO innerHTML / outerHTML / insertAdjacentHTML
*  - Plain SVG and DOM manipulation
*  - d3-force simulation layout
*/
var SVG_NS = "http://www.w3.org/2000/svg";
var WIDTH = 600;
var HEIGHT = 450;
function getEl(id) {
	const el = document.getElementById(id);
	if (!el) throw new Error(`Missing element #${id}`);
	return el;
}
function getSvgEl(id) {
	const el = document.getElementById(id);
	if (!el) throw new Error(`Missing SVG element #${id}`);
	return el;
}
document.addEventListener("DOMContentLoaded", () => {
	const tierBadge = getEl("tier-badge");
	const refreshBtn = getEl("refresh-btn");
	const optionsLink = getEl("options-link");
	const proBanner = getEl("pro-banner");
	const apexDomainVal = getEl("apex-domain-val");
	const nodesCountVal = getEl("nodes-count-val");
	const edgesCountVal = getEl("edges-count-val");
	const graphLoading = getEl("graph-loading");
	const graphEmpty = getEl("graph-empty");
	const edgesGroup = getSvgEl("edges-group");
	const nodesGroup = getSvgEl("nodes-group");
	const nodeDetails = getEl("node-details");
	const nodeHostname = getEl("node-hostname");
	const closeDetailsBtn = getEl("close-details-btn");
	const nodeRole = getEl("node-role");
	const nodeDiscoveredVia = getEl("node-discovered-via");
	const nodeGrade = getEl("node-grade");
	const nodeLastSeen = getEl("node-last-seen");
	let activeTabId = null;
	let activeApexDomain = "";
	optionsLink.addEventListener("click", (e) => {
		e.preventDefault();
		if (chrome.runtime.openOptionsPage !== void 0) chrome.runtime.openOptionsPage();
	});
	refreshBtn.addEventListener("click", () => {
		if (activeApexDomain.length > 0) fetchAndRenderGraph(activeApexDomain, activeTabId);
	});
	closeDetailsBtn.addEventListener("click", () => {
		nodeDetails.hidden = true;
	});
	const port = chrome.runtime.connect({ name: SIDEPANEL_PORT_NAME });
	port.onMessage.addListener((msg) => {
		const message = msg;
		if (message.type === "TAB_STATE_UPDATE" && message.state !== void 0) handleTabState(message.state);
	});
	(async () => {
		try {
			const urlParams = new URLSearchParams(window.location.search);
			const paramApex = urlParams.get("apex");
			const paramTabId = urlParams.get("tabId");
			if (paramApex !== null && paramApex.length > 0) {
				const cleanApex = registrableDomain(paramApex) ?? paramApex;
				activeApexDomain = cleanApex;
				const tabIdNum = paramTabId !== null && paramTabId.length > 0 ? parseInt(paramTabId, 10) : null;
				activeTabId = Number.isNaN(tabIdNum) ? null : tabIdNum;
				if (activeTabId !== null) port.postMessage({
					type: "REQUEST_STATE",
					tabId: activeTabId
				});
				fetchAndRenderGraph(cleanApex, activeTabId);
				return;
			}
			const tab = (await chrome.tabs.query({
				active: true,
				currentWindow: true
			}))[0];
			if (tab !== void 0 && tab.id !== void 0 && tab.url !== void 0 && tab.url.length > 0 && !tab.url.startsWith("chrome-extension://") && !tab.url.startsWith("moz-extension://")) {
				activeTabId = tab.id;
				port.postMessage({
					type: "REQUEST_STATE",
					tabId: tab.id
				});
				const origin = new URL(tab.url).origin;
				const hostname = new URL(origin).hostname;
				const apex = registrableDomain(hostname) ?? hostname;
				activeApexDomain = apex;
				fetchAndRenderGraph(apex, tab.id);
			} else {
				graphLoading.hidden = true;
				graphEmpty.textContent = "No inspectable tab active. Open a website to view its attack surface graph.";
				graphEmpty.hidden = false;
			}
		} catch {
			graphLoading.hidden = true;
			graphEmpty.textContent = "Unable to query active tab.";
			graphEmpty.hidden = false;
		}
	})();
	function handleTabState(state) {
		try {
			activeTabId = state.tabId;
			const host = new URL(state.origin).hostname;
			const apex = registrableDomain(host) ?? host;
			if (apex !== activeApexDomain) {
				activeApexDomain = apex;
				fetchAndRenderGraph(apex, state.tabId);
			}
		} catch {}
	}
	async function fetchAndRenderGraph(apexDomain, tabId) {
		graphLoading.hidden = false;
		graphEmpty.hidden = true;
		apexDomainVal.textContent = apexDomain;
		try {
			const response = await sendToBackground(tabId !== null ? {
				type: "REQUEST_GRAPH",
				apexDomain,
				tabId
			} : {
				type: "REQUEST_GRAPH",
				apexDomain
			});
			if (response.type === "GRAPH_RESPONSE" && response.graph !== void 0) renderGraph(response.graph);
			else {
				graphLoading.hidden = true;
				graphEmpty.hidden = false;
			}
		} catch (err) {
			graphLoading.hidden = true;
			graphEmpty.textContent = `Failed to load graph: ${err instanceof Error ? err.message : String(err)}`;
			graphEmpty.hidden = false;
		}
	}
	function renderGraph(graph) {
		graphLoading.hidden = true;
		if (graph.isPro) {
			tierBadge.textContent = "PRO";
			tierBadge.className = "tier-badge pro";
			proBanner.hidden = true;
		} else {
			tierBadge.textContent = "Free Tier";
			tierBadge.className = "tier-badge free";
			proBanner.hidden = false;
		}
		nodesCountVal.textContent = graph.nodes.length.toString();
		edgesCountVal.textContent = graph.edges.length.toString();
		while (edgesGroup.firstChild) edgesGroup.removeChild(edgesGroup.firstChild);
		while (nodesGroup.firstChild) nodesGroup.removeChild(nodesGroup.firstChild);
		if (graph.nodes.length === 0) {
			graphEmpty.hidden = false;
			return;
		}
		graphEmpty.hidden = true;
		const centerX = WIDTH / 2;
		const centerY = HEIGHT / 2;
		const simNodes = graph.nodes.map((n) => {
			const isApex = n.isApex;
			return {
				...n,
				id: n.hostname,
				x: isApex ? centerX : centerX + (Math.random() - .5) * 200,
				y: isApex ? centerY : centerY + (Math.random() - .5) * 200
			};
		});
		const nodeMap = new Map(simNodes.map((n) => [n.hostname, n]));
		const simLinks = graph.edges.filter((e) => nodeMap.has(e.source) && nodeMap.has(e.target)).map((e) => ({
			source: e.source,
			target: e.target,
			type: e.type,
			severity: e.severity
		}));
		const lineElements = simLinks.map((link) => {
			const line = document.createElementNS(SVG_NS, "line");
			line.setAttribute("class", `edge-line edge-${link.type}`);
			line.setAttribute("stroke-width", "1.5");
			const title = document.createElementNS(SVG_NS, "title");
			const sHost = typeof link.source === "string" ? link.source : link.source.hostname;
			const tHost = typeof link.target === "string" ? link.target : link.target.hostname;
			title.textContent = `Vector: ${link.type.toUpperCase()} from ${sHost} to ${tHost}`;
			line.appendChild(title);
			edgesGroup.appendChild(line);
			return line;
		});
		const nodeGroups = simNodes.map((node) => {
			const g = document.createElementNS(SVG_NS, "g");
			g.setAttribute("class", "node-group");
			const circle = document.createElementNS(SVG_NS, "circle");
			circle.setAttribute("class", "node-circle");
			circle.setAttribute("r", node.isApex ? "14" : "9");
			let fillColor = "#64748b";
			if (node.isApex) fillColor = "#f59e0b";
			else if (node.grade === "A") fillColor = "#10b981";
			else if (node.grade === "B") fillColor = "#3b82f6";
			else if (node.grade === "C") fillColor = "#f59e0b";
			else if (node.grade === "D") fillColor = "#f97316";
			else if (node.grade === "F") fillColor = "#ef4444";
			circle.setAttribute("fill", fillColor);
			circle.setAttribute("stroke", node.isApex ? "#fbbf24" : "#1e293b");
			circle.setAttribute("stroke-width", node.isApex ? "2.5" : "1.5");
			const text = document.createElementNS(SVG_NS, "text");
			text.setAttribute("class", `node-label ${node.isApex ? "apex" : ""}`);
			text.setAttribute("y", node.isApex ? "24" : "18");
			text.setAttribute("text-anchor", "middle");
			text.textContent = formatNodeLabel(node.hostname, node.isApex);
			g.appendChild(circle);
			g.appendChild(text);
			g.addEventListener("click", () => {
				showNodeDetails(node);
			});
			nodesGroup.appendChild(g);
			return g;
		});
		simulation_default(simNodes).force("link", link_default(simLinks).id((d) => d.id).distance(85)).force("charge", manyBody_default().strength(-220)).force("center", center_default(centerX, centerY)).force("collide", collide_default().radius(26)).on("tick", () => {
			for (let i = 0; i < simLinks.length; i++) {
				const link = simLinks[i];
				const line = lineElements[i];
				if (link !== void 0 && line !== void 0) {
					const s = link.source;
					const t = link.target;
					line.setAttribute("x1", clamp(s.x ?? centerX, 15, 585).toString());
					line.setAttribute("y1", clamp(s.y ?? centerY, 15, 435).toString());
					line.setAttribute("x2", clamp(t.x ?? centerX, 15, 585).toString());
					line.setAttribute("y2", clamp(t.y ?? centerY, 15, 435).toString());
				}
			}
			for (let i = 0; i < simNodes.length; i++) {
				const node = simNodes[i];
				const g = nodeGroups[i];
				if (node !== void 0 && g !== void 0) {
					const cx = clamp(node.x ?? centerX, 20, 580);
					const cy = clamp(node.y ?? centerY, 20, 430);
					g.setAttribute("transform", `translate(${cx}, ${cy})`);
				}
			}
		});
		const apexNode = simNodes.find((n) => n.isApex);
		if (apexNode !== void 0) showNodeDetails(apexNode);
	}
	function formatNodeLabel(hostname, isApex) {
		if (isApex) return hostname;
		const parts = hostname.split(".");
		if (parts.length > 2) return parts[0] ?? hostname;
		return hostname;
	}
	function showNodeDetails(node) {
		nodeHostname.textContent = node.hostname;
		nodeRole.textContent = node.isApex ? "👑 Apex Domain (Central Authority)" : "Subdomain";
		nodeDiscoveredVia.textContent = node.discoveredVia.join(", ");
		nodeGrade.textContent = node.grade !== void 0 && node.score !== void 0 ? `${node.grade} (${node.score}/100)` : "Passive discovery (no direct visit yet)";
		nodeLastSeen.textContent = new Date(node.lastSeen).toLocaleTimeString();
		nodeDetails.hidden = false;
	}
	function clamp(val, min, max) {
		return Math.max(min, Math.min(max, val));
	}
});
//#endregion

//# sourceMappingURL=sidepanel.html-BhwGaSqV.js.map