'use strict';

// Data definition API for Impress Application Server

// Require definition file
//   fileName - load schema from fileName
//
api.definition.require = function(fileName) {
  if (!api.common.contains(fileName, '/')) {
    fileName = '../schemas/' + fileName;
  }
  var definition = null;
  try {
    definition = require(fileName);
  } catch(err) {}
  return definition;
};

// Walk through both data tree and definition tree
// and call function for each data item
//   data       -
//   definition -
//   name       -
//   path       -
//   callback(parent, data, definition, name, path)
//     parent     - item parent
//     data       - certain item
//     definition - data structures definition hash
//     name       - item name in parent
//     path       - path to current item
//     def        - parsed data definition
//   return hash
//     valid   - boolean is result valud
//     errors  - array or empty array
//
api.definition.walk = function(data, definition, name, callback) {
  var keys = definition ? Object.keys(definition) : [],
      path = '';
  name = name || keys[0];
  return api.definition.walkRecursive(null, data, definition, name, path, callback);
};

// Internal walk
//
api.definition.walkRecursive = function(parent, data, definition, name, path, callback) {
  var tpl = definition[name],
      key, subKey, item, template, def, itemPath, subItem, subItemPath, other;

  if (typeof(tpl) === 'string') {
    def = api.definition.parse(tpl);
    for (key in data) {
      item = data[key];
      itemPath = path + '.' + key;
      api.definition.walkRecursive(item, item, definition, def.name, itemPath, callback);
    }
  } else {
    var tplKeys = typeof(tpl) === 'object' ? Object.keys(tpl) : [],
        dataKeys = (typeof(data) === 'object' && data !== null) ? Object.keys(data) : [];
    other = false;

    var index = tplKeys.indexOf('_other');
    if (index >= -1) tplKeys.splice(index, 1);

    api.common.merge(dataKeys, tplKeys);

    for (var i = 0, len = dataKeys.length; i < len; i++) {
      key = dataKeys[i];

      item = data ? data[key] : '';
      if (tpl) {
        template = tpl[key];
        if (!template) {
          template = tpl._other;
          other = true;
        }
      }
      itemPath = path + '.' + key;
      def = api.definition.parse(template);

      callback(data, item, template, key, itemPath, def);

      if (item) {
        if (def.type === 'struct') {
          api.definition.walkRecursive(data, item, definition, def.name, itemPath, callback);
        } else if (def.type === 'collection' && typeof(item) === 'object') {
          if (other) {
            api.definition.walkRecursive(data, item, definition, def.name, itemPath, callback);
          } else {
            for (subKey in item) {
              subItem = item[subKey];
              subItemPath = itemPath + '.' + subKey;
              api.definition.walkRecursive(item, subItem, definition, def.name, subItemPath, callback);
            }
          }
        }
      }

    }
  }
};

// JavaScript types
//
api.definition.types = [
  'number', 'string', 'array', 'boolean',
  'file', 'size', 'duration',
  'set',        // (one,two,three)
  'struct',     // {structName}
  'collection', // {{collection}}
  '*',          // * is anything
  'unknown'     // all other types
];

var definitionRx = new RegExp('[' + api.common.escapeRegExp('[]{}()') + ']', 'g');

// Parse field definition from schema
//   tpl - field definition
//   result:
//     type - field type, see: api.definition.types
//     name - struct name or collection name
//     default - default value
//     optional - is field optional, boolean flag
//     variants - set variants
//     comment - substring after '//'
//
api.definition.parse = function(tpl) {
  tpl = tpl + '';
  if (!tpl) return { type: 'unknown' };
  var comment, commentPos = tpl.indexOf('//');
  if (commentPos !== -1) {
    comment = api.common.trim(tpl.substring());
    tpl = api.common.trim(tpl.substring(0, commentPos));
  }
  if (typeof(tpl) === 'object') return { type: 'hash', str: tpl };
  var def = { type:'', optional: api.common.contains(tpl, '[') || api.common.contains(tpl, ':') },
      name = tpl.replace(definitionRx, '');
  if (api.common.contains(tpl, '{{')) def.type = 'collection';
  if (def.type !== 'collection' && api.common.contains(tpl, '{')) def.type = 'struct';
  if (api.common.contains(tpl, '(')) def.type = 'set';
  if (api.common.contains(name, ':')) {
    var valType = name.split(':');
    def.default = valType[0];
    def.type = valType[1];
  } else if (!def.type) def.type = name;
  else if (def.type === 'set') def.variants = name.split(',');
  else def.name = name;
  def.str = tpl;
  return def;
};

// Walk through data structures, add default values, convert size and duration to numbers
//
api.definition.preprocess = function(data, definition, definitionName, path) {
  return api.definition.walk(data, definition, definitionName, api.definition.preprocessValue);
};

// Preprocess single value
//   parent - object/hash containing given data
//   data - value of given data
//   definition - metadata definition of whole data structure
//   name - name of given data within parent hash
//   path - dot-separated path to the given data
//   def - metadata definition of given data
//
api.definition.preprocessValue = function(parent, data, definition, name, path, def) {
  if (def.type === 'size') parent[name] = api.common.sizeToBytes(data);
  else if (def.type === 'duration') parent[name] = api.common.duration(data);
  else if (def.type === 'number') parent[name] = api.definition.parseNumber(data);
  else if (def.type === 'boolean' && typeof(data) !== 'boolean') parent[name] = data === 'true';
};

// Parse number
//   s - string containing integer or float number
// Result: number or undefined
//
api.definition.parseNumber = function(s) {
  var n = parseFloat(s);
  if (isNaN(n)) return;
  else return n;
};

// Check data definition validity
//   data - data to validate
//   definition - definition hash
//   name - definition name in definition hash
//   preprocess - flag for data preprocessing (default false)
//
api.definition.validate = function(data, definition, name, preprocess) {
  var result = { valid: true, errors: [] };
  api.definition.walk(data, definition, name, function(parent, data, definition, name, path, def) {
    var dataType = typeof(data),
        itemValid;
    if (dataType === 'undefined') {
      parent[name] = def.default;
      data = def.default;
      dataType = typeof(data);
    }
    if (preprocess) {
      api.definition.preprocessValue(parent, data, definition, name, path, def);
      data = parent[name];
      dataType = typeof(data);
    }
    if (def.type !== 'undefined') {
      var types = {
        'number':   ['number'],
        'string':   ['string'],
        'boolean':  ['boolean'],
        'file':     ['string'],
        'size':     ['string', 'number'],
        'duration': ['string', 'number'],
        'struct':   ['object'],
        'hash':     ['object']
      };
      if (def.type === '*' || def.optional && dataType === 'undefined') itemValid = true;
      else if (def.type === 'set') itemValid = api.common.inArray(def.variants, data);
      else if (def.type === 'array') itemValid = Array.isArray(data);
      else if (def.type === 'collection') itemValid = api.common.inArray(['array', 'object'], typeof(parent));
      else itemValid = api.common.inArray(types[def.type], dataType);
      if (!itemValid) result.errors.push({
        path: path,
        error: 'Unexpected value "' + data + '" for definition: ' + def.str
      });
      result.valid = result.valid && itemValid;
    } else {
      result.valid = false;
      result.errors.push({ path: path, error: 'Unexpected name "' + name + '"' });
    }
  });
  return result;
};

// Print errors if not valid
//   message - error message
//   validationResult - result returned from api.definition.validate
//
api.definition.printErrors = function(message, validationResult) {
  if (!validationResult.valid) {
    console.log(message);
    var error;
    for (var i = 0, len = validationResult.errors.length; i < len; i++) {
      error = validationResult.errors[i];
      console.log('  ' + error.path.bold + ' - ' + error.error.red.bold);
    }
  }
};
