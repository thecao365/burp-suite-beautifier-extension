function unpacker_filter(source) {
    var trailing_comments = '';
    var comment = '';
    var found = false;

    do {
        found = false;
        if (/^\s*\/\*/.test(source)) {
            found = true;
            comment = source.substr(0, source.indexOf('*/') + 2);
            source = source.substr(comment.length).replace(/^\s+/, '');
            trailing_comments += comment + "\n";
        } else if (/^\s*\/\//.test(source)) {
            found = true;
            comment = source.match(/^\s*\/\/.*/)[0];
            source = source.substr(comment.length).replace(/^\s+/, '');
            trailing_comments += comment + "\n";
        }
    } while (found);

    if (P_A_C_K_E_R.detect(source)) {
        // P.A.C.K.E.R unpacking may fail, even though it is detected
        var unpacked = P_A_C_K_E_R.unpack(source);
        if (unpacked != source) {
            source = unpacker_filter(unpacked);
        }
    }
    if (Urlencoded.detect(source)) {
        source = unpacker_filter(Urlencoded.unpack(source))
    }
    if (JavascriptObfuscator.detect(source)) {
        source = unpacker_filter(JavascriptObfuscator.unpack(source))
    }
    if (MyObfuscate.detect(source)) {
        source = unpacker_filter(MyObfuscate.unpack(source))
    }

    return trailing_comments + source;
}


function looks_like_html(source)
{
    // <foo> - looks like html
    // <!--\nalert('foo!');\n--> - doesn't look like html

    var trimmed = source.replace(/^[ \t\n\r]+/, '');
    var comment_mark = '<!-' + '-';
    return (trimmed && (trimmed.substring(0, 1) === '<' && trimmed.substring(0, 4) !== comment_mark));
}


function beautify(source) {
    var indent_size = 1;
    var indent_char = indent_size == 1 ? '\t' : ' ';
    var preserve_newlines = true;
    var keep_array_indentation = false;
    var indent_scripts = 'normal';
    var brace_style = 'expand';
    var space_before_conditional = false;
	var detect_packers = true;
	
	var result = source;
    var opts = {
                indent_size: indent_size,
                indent_char: indent_char,
                preserve_newlines:preserve_newlines,
                brace_style: brace_style,
                keep_array_indentation:keep_array_indentation,
                space_after_anon_function:true,
                space_before_conditional: space_before_conditional,
                indent_scripts:indent_scripts};

    if (looks_like_html(source)) {
        result = style_html(source, opts);

    } else {
        if (detect_packers) {
            source = unpacker_filter(source);
        }
        var result = js_beautify(source, opts);
    }
	
	return result;
}