'use strict';

var repeater = function( pattern, count ) {
    var result = '';

    if ( !pattern || !count ) {
        throw 'Pattern and count are required fields.';
    }

    if ( pattern !== pattern.toString() && pattern.toString().indexOf('[object') > -1 ) {
        throw 'Pattern must be a string.';
    }

    count = parseInt( count, 10 );

    while ( count > 0 ) {
    /* jshint ignore:start */
        if ( count & 1 ) {
            result += pattern;
        }

        count >>= 1;
    /* jshint ignore:end */

        pattern += pattern;
    }

    return result;
};

module.exports = repeater;
