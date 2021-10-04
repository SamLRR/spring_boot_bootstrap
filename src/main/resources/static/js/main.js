$(document).ready(function () {
    $('.table .eBtn').on('click', function (event) {
        event.preventDefault();
        var href = $(this).attr('href');
        $.get(href, function (user, status) {
            $('.formEdit #id').val(user.id);
            $('.formEdit #firstName').val(user.firstName);
            $('.formEdit #lastName').val(user.lastName);
            $('.formEdit #age').val(user.age);
            $('.formEdit #userName').val(user.userName);
            $('.formEdit #password').val(user.password);
            $('.formEdit #roles').val(user.roles);

        });
        $('.formEdit #modalEdit').modal();
    });

    $('.table .delBtn').on('click', function (event) {
        event.preventDefault();
        var href = $(this).attr('href');
        $.get(href, function (user, status) {
            $('.formDelete #id1').val(user.id);
            $('.formDelete #firstName1').val(user.firstName);
            $('.formDelete #lastName1').val(user.lastName);
            $('.formDelete #age1').val(user.age);
            $('.formDelete #userName1').val(user.userName);
            $('.formDelete #roles1').val(user.roles);

        });

        $('.formDelete #modalDelete').modal();
    });
});