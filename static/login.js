$('login_btn').on('click', function () {
    $.ajax({
        url: '/login',
        data: $('form').serialize(),
        type: 'POST',
        datatype : 'json',
        success: function (data, textStatus) {
            if (data.redirect){
                window.location.href = data.redirect;
            }
            else {
                $("#form").replaceWith(data.form);
            }
            console.log(response);
        },
        error: function (error) {
            console.log(error);
        }
    });
});
