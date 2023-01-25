'use strict';

var repeater = require('text-repeater');

var billboard = function( message, promptWidth ) {
    if ( !message ) {
        throw 'message is required.';
    }

    if ( message !== message.toString() && message.toString().indexOf('[object') > -1 ) {
        throw 'message must be a string.';
    }

    promptWidth = parseInt( promptWidth, 10 );

    var messageLength = message.length;

    if ( !promptWidth || promptWidth < ( messageLength + 2 ) ) {
        promptWidth = messageLength + 4;
    }

    var spacesCount = ( promptWidth - messageLength - 2 ) / 2,
        spaces = repeater(' ', spacesCount),
        frameHorizontal = repeater( '-', promptWidth - 2 );

    if ( messageLength % 2 !== 0 ) {
        message += ' ';
    }

    var signage = [
        '',
        '.' + frameHorizontal + '.',
        '|' + spaces + message + spaces + '|',
        '\'' + frameHorizontal + '\'',
        ''
    ].join('\n') + '\n';

    return signage;
};

module.exports = billboard;
