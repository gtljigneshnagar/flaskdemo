$(document).ready(function() {
    $('form').on('submit', function() {
        var url = "{{ url_for('signup') }}";
        $.ajax({
            url: url,
            data: $('form').serialize(),
            type: 'POST',
            success: function (data) {
                //$(location).attr('href', '/index')
                console.log(response);
            },
            error : function (error) {
                console.log(error);
            }
        });
    });

    $.ajaxSetup({
        beforeSend: function(xhr, settings) {
            if (!/^(GET|HEAD|OPTIONS|TRACE)$/i.test(settings.type) && !this.crossDomain) {
                xhr.setRequestHeader("X-CSRFToken", "{{ form.csrf_token._value() }}")
            }
        }
    })
});
