from django.contrib import admin

from django.contrib.auth.admin import UserAdmin, GroupAdmin, Group

from django.utils.text import gettext_lazy as _

from .models import User, Role, AuthTransaction, OTPValidation


class DRFUserAdmin(UserAdmin):
    """
    Overrides UserAdmin to show fields name & mobile and remove fields:
    first_name, last_name
    """
    fieldsets = (
        (None, {'fields': ('username', 'password')}),
        (_('Personal info'), {'fields': ('name', 'email', 'mobile')}),
        (_('Permissions'), {'fields': ('is_active', 'is_staff',
                                       'is_superuser','groups',
                                       'user_permissions')}),
        (_('Important dates'), {'fields': ('last_login', 'date_joined',
                                           'update_date')}),
    )
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('username', 'email', 'mobile', 'password1',
                       'password2'),
        }),
    )
    list_display = ('username', 'email', 'name', 'mobile', 'is_staff')
    search_fields = ('username', 'name', 'email', 'mobile')
    readonly_fields = ('date_joined', 'last_login', 'update_date')


class OTPValidationAdmin(admin.ModelAdmin):
    list_display = ('destination', 'otp', 'prop')


# UnRegister default Group & register proxy model Role
# This will also remove additional display of application in admin panel.
# Source: https://stackoverflow.com/a/32445368
admin.site.unregister(Group)
admin.site.register(Role, GroupAdmin)

admin.site.register(User, DRFUserAdmin)
admin.site.register(OTPValidation, OTPValidationAdmin)
admin.site.register(AuthTransaction)
