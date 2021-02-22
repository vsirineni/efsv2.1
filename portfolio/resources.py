# resources.py
from import_export import resources
from .models import Customer


class CustomerResource(resources.CustomerResource):
    class Meta:
        model = Customer