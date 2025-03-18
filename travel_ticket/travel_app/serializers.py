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
        return 
    
class TravelRequestSerializer(serializers.ModelSerializer):
    """Serializer for travel request details."""
    class Meta:
        model = TravelApplication
        fields = ['id', 'employee_name', 'manager_name', 'from_location', 'to_location', 
                'start_date', 'end_date', 'status', 'is_closed']
        
class TravelApplicationSerializer(serializers.ModelSerializer):
    class Meta:
        model = TravelApplication
        fields = '__all__'


# ========================== Admin Serializers ==========================
class AdminCreateSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField(write_only=True)
    email = serializers.EmailField()


class AdminDetailSerializer(serializers.ModelSerializer):
    """
    Serializer for admin data representation
    """
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

class EmployeeTravelRequestViewSerializer(serializers.ModelSerializer):
    """Used by employee to view own travel requests"""
    approved_by = serializers.SerializerMethodField()
    manager_id = serializers.IntegerField(source='manager.id', read_only=True)

    class Meta:
        model = TravelApplication
        fields = [
            'id', 'approved_by', 'manager_id', 'from_location', 'to_location', 'start_date',
            'end_date', 'status', 'travel_mode', 'lodging_required', 'purpose'
        ]

    def get_approved_by(self, obj):
        """Return the manager's full name"""
        if obj.manager:
            return f"{obj.manager.first_name} {obj.manager.last_name}"
        return None

class ManagerTravelApprovalSerializer(serializers.ModelSerializer):
    """Used by manager to manage employee requests"""
    applicant = serializers.CharField(source='employee.first_name', read_only=True)

    class Meta:
        model = TravelApplication
        fields = ['id', 'applicant', 'status']


class AdminTravelOverviewSerializer(serializers.ModelSerializer):
    """Used by admin for full view of travel requests"""
    employee_name = serializers.CharField(source='employee.first_name', read_only=True)
    manager_name = serializers.CharField(source='manager.first_name', read_only=True)

    class Meta:
        model = TravelApplication
        fields = ['id', 'employee_name', 'manager_name', 'from_location', 'to_location',
                'start_date', 'end_date', 'status', 'is_closed']