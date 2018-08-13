from django.contrib import admin
from .models import *


class UserAdmin(admin.ModelAdmin):

    list_display = ('name', 'mobile', 'email')
    search_fields = ('name', 'mobile')


class OTPValidationAdmin(admin.ModelAdmin):
    list_display = ('destination', 'otp', 'type')


admin.site.register(User, UserAdmin)
admin.site.register(OTPValidation, OTPValidationAdmin)
admin.site.register(AuthTransaction)
