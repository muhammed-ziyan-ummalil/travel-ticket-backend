from django.db import models
from django.contrib.auth.models import User

# ========================== Extended User Profile ==========================

class Profile(models.Model):
    """Extended user role and status profile"""
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='extended_profile')

    ROLE_CHOICES = [
        ("manager", "Manager"),
        ("employee", "Employee"),
    ]
    role = models.CharField(max_length=20, choices=ROLE_CHOICES)

    STATUS_CHOICES = [
        ("active", "Active"),
        ("inactive", "Inactive"),
        ('closed', 'Closed'),
    ]
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="active")

    def __str__(self):
        return f"{self.user.username} ({self.role})"


# ========================== Admin Model ==========================

class AdminUser(models.Model):
    """Model for system administrator"""
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='admin_info')
    username = models.CharField(max_length=100, unique=True)
    password = models.CharField(max_length=100)  # Should be stored hashed
    email = models.EmailField(max_length=100, unique=True)

    def __str__(self):
        return self.username


# ========================== Manager Model ==========================

class ManagerProfile(models.Model):
    """Details specific to managers"""
    profile = models.OneToOneField(Profile, on_delete=models.CASCADE, related_name='manager_info')
    first_name = models.CharField(max_length=100)
    last_name = models.CharField(max_length=100)
    gender = models.CharField(max_length=15, default="Not Specified")
    email = models.EmailField(max_length=100, unique=True)
    designation = models.CharField(max_length=50, default="HR")
    status = models.CharField(max_length=20, choices=Profile.STATUS_CHOICES, default="active")

    def __str__(self):
        return f"Manager: {self.first_name} {self.last_name}"


# ========================== Employee Model ==========================

class EmployeeProfile(models.Model):
    """Details specific to employees"""
    profile = models.OneToOneField(Profile, on_delete=models.CASCADE, related_name='employee_info')
    first_name = models.CharField(max_length=100)
    last_name = models.CharField(max_length=100)
    gender = models.CharField(max_length=15, default="Not Specified")
    email = models.EmailField(max_length=100, unique=True)
    designation = models.CharField(max_length=50, default="HR")
    status = models.CharField(max_length=20, choices=Profile.STATUS_CHOICES, default="active")
    manager = models.ForeignKey(ManagerProfile, on_delete=models.SET_NULL, null=True, blank=True)

    def __str__(self):
        return f"Employee: {self.first_name} {self.last_name}"


# ========================== Travel Request Model ==========================

class TravelApplication(models.Model):
    """Travel request lifecycle management"""
    employee = models.ForeignKey(EmployeeProfile, on_delete=models.SET_NULL, null=True, blank=True)
    manager = models.ForeignKey(ManagerProfile, on_delete=models.SET_NULL, null=True, blank=True)

    from_location = models.CharField(max_length=50)
    to_location = models.CharField(max_length=50)

    TRAVEL_MODE_CHOICES = [
        ("Air", "Air"),
        ("Ship", "Ship"),
        ("Train", "Train"),
        ("Bus", "Bus"),
        ("Car", "Car"),
    ]
    travel_mode = models.CharField(max_length=20, choices=TRAVEL_MODE_CHOICES)

    start_date = models.DateField()
    end_date = models.DateField()

    hotel_preference = models.CharField(max_length=100, blank=True, null=True)
    lodging_required = models.BooleanField(default=False)

    additional_notes = models.CharField(max_length=100, blank=True, null=True)
    manager_notes = models.CharField(max_length=100, blank=True, null=True)
    admin_notes = models.CharField(max_length=100, blank=True, null=True)
    purpose = models.CharField(max_length=200, blank=True, null=True)

    STATUS_CHOICES = [
        ("approved", "Approved"),
        ("pending", "Pending"),
        ("rejected", "Rejected"),
        ("closed", "Closed"),
        ("update", "Update"),
    ]
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="pending")

    is_closed = models.BooleanField(default=False)
    is_resubmitted = models.BooleanField(default=False)

    date_submitted = models.DateField(auto_now_add=True)
    update_submitted_date = models.DateField(null=True, blank=True)
    resubmitted_date = models.DateField(null=True, blank=True)

    def __str__(self):
        return f"Travel: {self.from_location} → {self.to_location} ({self.status})"
