from django.contrib.auth.models import User
from rest_framework import serializers
from .models import Profile, AdminUser, ManagerProfile, EmployeeProfile, TravelApplication

# ========================== User & Profile Serializers ==========================

class ProfileInfoSerializer(serializers.ModelSerializer):
    """Handles serialization of user profile details along with user fields"""
    username = serializers.SerializerMethodField()
    email = serializers.SerializerMethodField()

    class Meta:
        model = Profile
        fields = ['id', 'username', 'email', 'role', 'status']

    def get_username(self, obj):
        return obj.user.username

    def get_email(self, obj):
        return obj.user.email


class UserRegistrationSerializer(serializers.ModelSerializer):
    """Handles creation of user with hashed password and role assignment"""
    password = serializers.CharField(write_only=True)
    role = serializers.ChoiceField(choices=Profile.ROLE_CHOICES)

    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'password', 'role']

    def create(self, validated_data):
        role = validated_data.pop('role')
        user = User.objects.create_user(
            username=validated_data.get('username'),
            email=validated_data.get('email'),
            password=validated_data.get('password')
        )
        Profile.objects.create(user=user, role=role)
        return user


# ========================== Admin Serializers ==========================

class AdminCreateSerializer(serializers.Serializer):
    """Handles admin creation"""
    username = serializers.CharField()
    password = serializers.CharField(write_only=True)
    email = serializers.EmailField()


class AdminDetailSerializer(serializers.ModelSerializer):
    """Serializer for admin data representation"""
    username = serializers.SerializerMethodField()
    email = serializers.SerializerMethodField()

    class Meta:
        model = AdminUser
        fields = ['id', 'username', 'email']

    def get_username(self, obj):
        return obj.user.username

    def get_email(self, obj):
        return obj.user.email


# ========================== Manager Serializers ==========================

class ManagerDetailSerializer(serializers.ModelSerializer):
    """Serializer for manager data"""
    profile = ProfileInfoSerializer()

    class Meta:
        model = ManagerProfile
        fields = ['id', 'profile', 'first_name', 'last_name', 'email', 'designation', 'status']


# ========================== Employee Serializers ==========================

class EmployeeDetailSerializer(serializers.ModelSerializer):
    """Serializer for employee data"""
    profile = ProfileInfoSerializer()
    reporting_manager = serializers.PrimaryKeyRelatedField(
        queryset=ManagerProfile.objects.all(), allow_null=True, source='manager'
    )

    class Meta:
        model = EmployeeProfile
        fields = ['id', 'profile', 'first_name', 'last_name', 'email', 'designation', 'status', 'reporting_manager']


# ========================== Travel Request Serializers ==========================

class TravelApplicationSerializer(serializers.ModelSerializer):
    """Full travel application serializer"""
    class Meta:
        model = TravelApplication
        fields = '__all__'


class EmployeeTravelRequestViewSerializer(serializers.ModelSerializer):
    """Used by employee to view own travel requests"""
    request_id = serializers.IntegerField(source='id', read_only=False)
    from_date = serializers.DateField(source='start_date', format='%Y-%m-%d', read_only=False)
    to_date = serializers.DateField(source='end_date', format='%Y-%m-%d', read_only=False)
    approved_by = serializers.SerializerMethodField()
    manager_id = serializers.IntegerField(source='manager.id', read_only=True)
    manager_status = serializers.SerializerMethodField()
    admin_status = serializers.SerializerMethodField()
    
    # ✅ Add employee_name here
    employee_name = serializers.CharField(source='employee.first_name', read_only=True)

    class Meta:
        model = TravelApplication
        fields = [
            'request_id', 'from_date', 'to_date', 'approved_by', 'manager_id',
            'from_location', 'to_location', 'status', 'travel_mode',
            'lodging_required', 'purpose', 'hotel_preference', 'additional_notes',
            'manager_notes', 'admin_notes', 'requested_for_info',
            'employee_response', 'info_requested_date', 'response_date',
            'date_submitted', 'update_submitted_date', 'resubmitted_date',
            'manager_status', 'admin_status',
            'employee_name'  
        ]

    def get_approved_by(self, obj):
        """Return the manager's full name"""
        if obj.manager:
            return f"{obj.manager.first_name} {obj.manager.last_name}"
        return None

    def get_manager_status(self, obj):
        """Return manager status based on manager notes"""
        if obj.manager_notes:
            return "Reviewed" if obj.status == "pending" else obj.status
        return "Pending"

    def get_admin_status(self, obj):
        """Return admin status based on admin notes"""
        if obj.admin_notes:
            return "Reviewed" if obj.status == "pending" else obj.status
        return "Pending"



class ManagerTravelApprovalSerializer(serializers.ModelSerializer):
    """Used by manager to manage employee requests"""
    applicant = serializers.CharField(source='employee.first_name', read_only=True)

    class Meta:
        model = TravelApplication
        fields = ['id', 'applicant', 'status', 'manager_notes', 'requested_for_info']


class AdminTravelOverviewSerializer(serializers.ModelSerializer):
    """Used by admin for full view of travel requests"""
    employee_name = serializers.CharField(source='employee.first_name', read_only=True)
    manager_name = serializers.CharField(source='manager.first_name', read_only=True)

    class Meta:
        model = TravelApplication
        fields = [
            'id', 'employee_name', 'manager_name', 'from_location', 'to_location',
            'start_date', 'end_date', 'status', 'is_closed', 'admin_notes'
        ]


class EmployeeResubmitRequestSerializer(serializers.ModelSerializer):
    """Used by employee to resubmit a request with additional info"""
    class Meta:
        model = TravelApplication
        fields = ['employee_response', 'status', 'resubmitted_date']

    def update(self, instance, validated_data):
        """Update request and mark as resubmitted"""
        instance.employee_response = validated_data.get('employee_response', instance.employee_response)
        instance.status = 'resubmitted'
        instance.resubmitted_date = validated_data.get('resubmitted_date', instance.resubmitted_date)
        instance.save()
        return instance


class TravelRequestSerializer(serializers.ModelSerializer):
    """Serializer for travel request details."""
    employee_name = serializers.CharField(source='employee.first_name', read_only=True)
    manager_name = serializers.CharField(source='manager.first_name', read_only=True)

    class Meta:
        model = TravelApplication
        fields = [
            'id', 'employee_name', 'manager_name', 'from_location', 'to_location',
            'start_date', 'end_date', 'status', 'is_closed', 'hotel_preference',
            'additional_notes', 'date_submitted', 'update_submitted_date', 'resubmitted_date'
        ]

