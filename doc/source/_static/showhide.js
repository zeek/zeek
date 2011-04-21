// make literal blocks corresponding to identifier initial values
// hidden by default
$(document).ready(function() {

    var showText='(Show Value)';
    var hideText='(Hide Value)';

    var is_visible = false;

    // select field-list tables that come before a literal block
    tables = $('.highlight-python').prev('table.docutils.field-list');

    tables.find('th.field-name').filter(function(index) {
        return $(this).html() == "Default :";
    }).next().append('<a href="#" class="toggleLink">'+showText+'</a>');

    // hide all literal blocks that follow a field-list table
    tables.next('.highlight-python').hide();

    // register handler for clicking a "toggle" link
    $('a.toggleLink').click(function() {
        is_visible = !is_visible;

        $(this).html( (!is_visible) ? showText : hideText);

        // the link is inside a <table><tbody><tr><td> and the next
        // literal block after the table is the literal block that we want
        // to show/hide
        $(this).parent().parent().parent().parent().next('.highlight-python').slideToggle('fast');

        // override default link behavior
        return false;
    });
});

// make "Private Interface" sections hidden by default
$(document).ready(function() {

    var showText='Show Private Interface (for internal use)';
    var hideText='Hide Private Interface';

    var is_visible = false;

    // insert show/hide links
    $('#private-interface').children(":first-child").after('<a href="#" class="privateToggle">'+showText+'</a>');

    // wrap all sub-sections in a new div that can be hidden/shown
    $('#private-interface').children(".section").wrapAll('<div class="private" />');

    // hide the given class
    $('.private').hide();

    // register handler for clicking a "toggle" link
    $('a.privateToggle').click(function() {
        is_visible = !is_visible;

        $(this).html( (!is_visible) ? showText : hideText);

        $('.private').slideToggle('fast');

        // override default link behavior
        return false;
    });
});
