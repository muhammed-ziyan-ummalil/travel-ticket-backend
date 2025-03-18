# from rest_framework.decorators import api_view, authentication_classes, permission_classes
# from rest_framework.permissions import IsAuthenticated
# from rest_framework.authentication import TokenAuthentication
# from rest_framework.response import Response
# from rest_framework.status import (
#     HTTP_200_OK,
#     HTTP_201_CREATED,
#     HTTP_400_BAD_REQUEST,
#     HTTP_404_NOT_FOUND,
# )
# from datetime import date

# from travel_app.models import TravelRequest, Employee
# from travel_app.serializers import TravelRequestSerializer


# @api_view(["GET"])
# @permission_classes([IsAuthenticated])
# def get_employee_dashboard(request):
#     """
#     Retrieve all travel requests submitted by the authenticated employee.
#     """
#     try:
#         employee = Employee.objects.get(user_profile__user=request.user)
#         travel_requests = TravelRequest.objects.filter(employee=employee)
#         serializer = TravelRequestSerializer(travel_requests, many=True)
#         return Response(serializer.data, status=HTTP_200_OK)
#     except Employee.DoesNotExist:
#         return Response({"error": "Employee profile not found."}, status=HTTP_404_NOT_FOUND)


# @api_view(["GET"])
# @permission_classes([IsAuthenticated])
# def get_employee_request_by_id(request, request_id):
#     """
#     Retrieve a specific travel request by ID.
#     """
#     try:
#         travel_request = TravelRequest.objects.get(id=request_id)
#         serializer = TravelRequestSerializer(travel_request)
#         return Response(serializer.data, status=HTTP_200_OK)
#     except TravelRequest.DoesNotExist:
#         return Response({"error": "Travel request not found."}, status=HTTP_404_NOT_FOUND)


# @api_view(["PUT"])
# @permission_classes([IsAuthenticated])
# def edit_employee_request(request, request_id):
#     """
#     Allows an employee to edit their travel request by ID.
#     """
#     try:
#         travel_request = TravelRequest.objects.get(id=request_id)
#     except TravelRequest.DoesNotExist:
#         return Response({"error": "Travel request not found."}, status=HTTP_404_NOT_FOUND)

#     serializer = TravelRequestSerializer(travel_request, data=request.data, partial=True)
#     if serializer.is_valid():
#         serializer.save()
#         return Response(
#             {
#                 "message": "Travel request updated successfully.",
#                 "data": serializer.data,
#             },
#             status=HTTP_200_OK
#         )
#     return Response(serializer.errors, status=HTTP_400_BAD_REQUEST)


# @api_view(["PUT"])
# @permission_classes([IsAuthenticated])
# def cancel_employee_request(request, request_id):
#     """
#     Allows an employee to cancel a travel request if:
#     - It is not approved or rejected.
#     - (Optional: You can uncomment to check if date is in the past.)
#     """
#     try:
#         travel_request = TravelRequest.objects.get(id=request_id)
#     except TravelRequest.DoesNotExist:
#         return Response({"error": "Travel request not found."}, status=HTTP_404_NOT_FOUND)

#     if travel_request.status in ["approved", "rejected"]:
#         return Response({"error": "Approved or rejected requests cannot be cancelled."}, status=HTTP_400_BAD_REQUEST)

#     # Optional: Check if travel date is in the past
#     # if travel_request.start_date > date.today():
#     #     return Response({"error": "Only past requests can be cancelled."}, status=HTTP_400_BAD_REQUEST)

#     travel_request.status = "cancelled"
#     travel_request.is_closed = True
#     travel_request.save()

#     return Response({"message": "Travel request cancelled successfully."}, status=HTTP_200_OK)


# @api_view(["POST"])
# @authentication_classes([TokenAuthentication])
# @permission_classes([IsAuthenticated])
# def submit_employee_request(request):
#     """
#     Allows an employee to submit a new travel request.
#     """
#     try:
#         employee = Employee.objects.get(user_profile__user=request.user)
#     except Employee.DoesNotExist:
#         return Response({"error": "Employee profile not found."}, status=HTTP_404_NOT_FOUND)

#     data = request.data
#     start_date_str = data.get("start_date")
#     end_date_str = data.get("end_date")

#     if not start_date_str or not end_date_str:
#         return Response({"error": "Start date and end date are required."}, status=HTTP_400_BAD_REQUEST)

#     try:
#         start_date = date.fromisoformat(start_date_str)
#         end_date = date.fromisoformat(end_date_str)
#     except ValueError:
#         return Response({"error": "Invalid date format. Use YYYY-MM-DD."}, status=HTTP_400_BAD_REQUEST)

#     if start_date < date.today():
#         return Response({"error": "Start date must be in the future."}, status=HTTP_400_BAD_REQUEST)

#     if end_date <= start_date:
#         return Response({"error": "End date must be after start date."}, status=HTTP_400_BAD_REQUEST)

#     serializer = TravelRequestSerializer(data=data)
#     if serializer.is_valid():
#         travel_request = serializer.save(employee=employee, manager=employee.manager)
#         return Response(
#             {
#                 "message": "Travel request submitted successfully.",
#                 "data": TravelRequestSerializer(travel_request).data,
#             },
#             status=HTTP_201_CREATED
#         )
#     return Response(serializer.errors, status=HTTP_400_BAD_REQUEST)


# @api_view(["PUT"])
# @permission_classes([IsAuthenticated])
# def resubmit_employee_request(request, request_id):
#     """
#     Allows an employee to resubmit a travel request if marked as 'requested_for_info'.
#     """
#     try:
#         travel_request = TravelRequest.objects.get(id=request_id)
#     except TravelRequest.DoesNotExist:
#         return Response({"error": "Travel request not found."}, status=HTTP_404_NOT_FOUND)

#     if travel_request.status != "pending":
#         return Response({"error": "Only requests requiring more info can be resubmitted."}, status=HTTP_400_BAD_REQUEST)

#     if not request.data:
#         return Response({"error": "At least one field must be updated before resubmission."}, status=HTTP_400_BAD_REQUEST)

#     serializer = TravelRequestSerializer(travel_request, data=request.data, partial=True)
#     if serializer.is_valid():
#         travel_request.status = "pending"
#         serializer.save()
#         return Response(
#             {
#                 "message": "Travel request resubmitted successfully.",
#                 "data": serializer.data,
#             },
#             status=HTTP_200_OK
#         )
#     return Response(serializer.errors, status=HTTP_400_BAD_REQUEST)

# @api_view(['GET'])
# def manager_view_requests(request):
#     """
#     Manager: View travel requests with optional filters.
#     """
#     try:
#         start_date = request.GET.get('start_date')
#         end_date = request.GET.get('end_date')
#         employee_name = request.GET.get('employee_name')
#         status_filter = request.GET.get('status')

#         requests = TravelRequest.objects.select_related('employee').all()

#         if start_date and end_date:
#             requests = requests.filter(travel_from__gte=start_date, travel_to__lte=end_date)
#         if employee_name:
#             requests = requests.filter(employee__name__icontains=employee_name)
#         if status_filter:
#             requests = requests.filter(status=status_filter)

#         serializer = TravelRequestSerializer(requests, many=True)
#         return Response(serializer.data, status=HTTP_200_OK)

#     except Exception as e:
#         return Response(
#             {"error": f"Failed to retrieve requests: {str(e)}"},
#             status=HTTP_500_INTERNAL_SERVER_ERROR
#         )


# @api_view(['GET'])
# def get_travel_requests(request):
#     """
#     Admin: View all travel requests with filters and sorting.
#     """
#     try:
#         start_date = request.GET.get('start_date')
#         end_date = request.GET.get('end_date')
#         employee_name = request.GET.get('employee_name')
#         status_filter = request.GET.get('status')
#         order_by = request.GET.get('order_by', 'id')

#         requests = TravelRequest.objects.select_related('employee').all()

#         if start_date and end_date:
#             requests = requests.filter(travel_from__gte=start_date, travel_to__lte=end_date)
#         if employee_name:
#             requests = requests.filter(employee__name__icontains=employee_name)
#         if status_filter:
#             requests = requests.filter(status=status_filter)

#         requests = requests.order_by(order_by)
#         serializer = TravelRequestSerializer(requests, many=True)
#         return Response(serializer.data, status=HTTP_200_OK)

#     except Exception as e:
#         return Response(
#             {"error": f"Failed to retrieve travel requests: {str(e)}"},
#             status=HTTP_500_INTERNAL_SERVER_ERROR
#         )


# @api_view(['GET'])
# def get_travel_request_details(request, request_id):
#     """
#     Get detailed info about a specific travel request.
#     """
#     try:
#         travel_request = TravelRequest.objects.select_related('employee').get(id=request_id)
#         serializer = TravelRequestSerializer(travel_request)
#         return Response(serializer.data, status=HTTP_200_OK)

#     except TravelRequest.DoesNotExist:
#         return Response({"error": "Travel request not found."}, status=HTTP_404_NOT_FOUND)

#     except Exception as e:
#         return Response({"error": f"Unexpected error: {str(e)}"}, status=HTTP_500_INTERNAL_SERVER_ERROR)


# @api_view(['PUT'])
# def update_travel_request_status(request, request_id):
#     """
#     Update status of a specific travel request.
#     """
#     try:
#         travel_request = TravelRequest.objects.get(id=request_id)
#         new_status = request.data.get("status")

#         if not new_status:
#             return Response({"error": "Status is required."}, status=HTTP_400_BAD_REQUEST)

#         travel_request.status = new_status
#         travel_request.save()

#         return Response(
#             {"message": "Status updated successfully.", "new_status": new_status},
#             status=HTTP_200_OK
#         )

#     except TravelRequest.DoesNotExist:
#         return Response({"error": "Travel request not found."}, status=HTTP_404_NOT_FOUND)

#     except Exception as e:
#         return Response({"error": f"Failed to update status: {str(e)}"}, status=HTTP_500_INTERNAL_SERVER_ERROR)


# @api_view(['DELETE'])
# def process_and_close_travel_request(request, request_id):
#     """
#     Delete an approved travel request (mark as closed).
#     """
#     try:
#         travel_request = TravelRequest.objects.get(id=request_id)

#         if travel_request.status != "Approved":
#             return Response(
#                 {"error": "Only approved requests can be closed."},
#                 status=HTTP_400_BAD_REQUEST
#             )

#         travel_request.delete()
#         return Response({"message": "Approved travel request closed successfully."}, status=HTTP_200_OK)

#     except TravelRequest.DoesNotExist:
#         return Response({"error": "Travel request not found."}, status=HTTP_404_NOT_FOUND)

#     except Exception as e:
#         return Response({"error": f"Error occurred: {str(e)}"}, status=HTTP_500_INTERNAL_SERVER_ERROR)


# @api_view(['GET'])
# def get_all_employees(request):
#     """
#     Get list of all employees.
#     """
#     employees = Employee.objects.all()
#     serializer = EmployeeSerializer(employees, many=True)
#     return Response(serializer.data, status=HTTP_200_OK)


# @api_view(['GET'])
# def get_all_managers(request):
#     """
#     Get list of all managers.
#     """
#     managers = Employee.objects.filter(role="Manager")
#     serializer = EmployeeSerializer(managers, many=True)
#     return Response(serializer.data, status=HTTP_200_OK)


# @api_view(['PUT'])
# def update_user(request, user_id):
#     """
#     Update an employee or manager's profile.
#     """
#     try:
#         user = Employee.objects.get(id=user_id)
#         serializer = EmployeeSerializer(user, data=request.data, partial=True)
#         if serializer.is_valid():
#             serializer.save()
#             return Response(serializer.data, status=HTTP_200_OK)
#         return Response(serializer.errors, status=HTTP_400_BAD_REQUEST)

#     except Employee.DoesNotExist:
#         return Response({"error": "User not found."}, status=HTTP_404_NOT_FOUND)


# @api_view(['DELETE'])
# def delete_user(request, user_id):
#     """
#     Delete an employee or manager account.
#     """
#     try:
#         user = Employee.objects.get(id=user_id)
#         user.delete()
#         return Response({"message": "User deleted successfully."}, status=HTTP_200_OK)

#     except Employee.DoesNotExist:
#         return Response({"error": "User not found."}, status=HTTP_404_NOT_FOUND)


# @api_view(['POST'])
# def request_additional_info(request, request_id):
#     """
#     Admin: Request additional info for a travel request via email.
#     """
#     try:
#         travel_request = TravelRequest.objects.select_related('employee').get(id=request_id)

#         travel_request.status = "Additional Info Required"
#         travel_request.save()

#         send_mail(
#             subject="Additional Information Required",
#             message=f"Dear {travel_request.employee.name},\n\n"
#                     "Please provide additional details for your travel request.",
#             from_email="admin@company.com",
#             recipient_list=[travel_request.employee.email],
#         )

#         return Response(
#             {"message": "Request for additional information sent successfully."},
#             status=HTTP_200_OK
#         )

#     except TravelRequest.DoesNotExist:
#         return Response({"error": "Travel request not found."}, status=HTTP_404_NOT_FOUND)

#     except Exception as e:
#         return Response({"error": f"Failed to request additional info: {str(e)}"}, status=HTTP_500_INTERNAL_SERVER_ERROR)
    
# @api_view(['POST'])
# def create_initial_admin(request):
#     """
#     Create the initial admin user if not already present.
#     """
#     if Admin.objects.exists():
#         return Response({"error": "Admin already exists."}, status=status.HTTP_400_BAD_REQUEST)

#     serializer = AdminSerializer(data=request.data)

#     if serializer.is_valid():
#         username = serializer.validated_data.get("username")
#         password = request.data.get("password")
#         email_id = serializer.validated_data.get("email_id")

#         if not password:
#             return Response({"error": "Password is required."}, status=status.HTTP_400_BAD_REQUEST)

#         user = User.objects.create_user(username=username, password=password, email=email_id)
#         hashed_password = make_password(password)

#         admin = Admin.objects.create(
#             user=user,
#             username=username,
#             password=hashed_password,
#             email_id=email_id
#         )

#         return Response({
#             "message": "Admin created successfully.",
#             "admin": AdminSerializer(admin).data
#         }, status=status.HTTP_201_CREATED)

#     return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# @api_view(['POST'])
# def admin_login(request):
#     """
#     Admin login view with token authentication.
#     """
#     username = request.data.get('username')
#     password = request.data.get('password')

#     if not username or not password:
#         return Response({"error": "Username and password are required."}, status=status.HTTP_400_BAD_REQUEST)

#     user = authenticate(username=username, password=password)

#     if user and hasattr(user, 'admin_profile'):
#         token, _ = Token.objects.get_or_create(user=user)
#         return Response({"message": "Login successful", "token": token.key}, status=status.HTTP_200_OK)

#     return Response({"error": "Invalid credentials or user is not an admin."}, status=status.HTTP_401_UNAUTHORIZED)


# @api_view(['POST'])
# def user_login(request):
#     """
#     Login view for manager and employee roles.
#     """
#     username = request.data.get('username')
#     password = request.data.get('password')

#     if not username or not password:
#         return Response({"error": "Username and password are required."}, status=status.HTTP_400_BAD_REQUEST)

#     user = authenticate(username=username, password=password)
#     if not user:
#         return Response({"error": "Invalid credentials."}, status=status.HTTP_401_UNAUTHORIZED)

#     user_profile = UserProfile.objects.filter(user=user).first()
#     if not user_profile:
#         return Response({"error": "User profile not found."}, status=status.HTTP_404_NOT_FOUND)

#     if user_profile.role not in ["manager", "employee"]:
#         return Response({"error": "Unauthorized user role."}, status=status.HTTP_403_FORBIDDEN)

#     token, _ = Token.objects.get_or_create(user=user)

#     return Response({
#         "message": "Login successful",
#         "token": token.key,
#         "role": user_profile.role,
#         "status": user_profile.status
#     }, status=status.HTTP_200_OK)


# @api_view(['POST'])
# @authentication_classes([TokenAuthentication])
# @permission_classes([IsAuthenticated])
# def user_logout(request):
#     """
#     Logout the current user by deleting their token.
#     """
#     try:
#         request.user.auth_token.delete()
#         return Response({"message": "Logout successful."}, status=status.HTTP_200_OK)
#     except Exception:
#         return Response({"error": "Something went wrong."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# @api_view(['POST'])
# @authentication_classes([TokenAuthentication])
# @permission_classes([IsAuthenticated])
# def add_user(request):
#     """
#     Add a new Manager or Employee (Only Admin can perform).
#     """
#     if not hasattr(request.user, 'admin_profile'):
#         return Response({"error": "Only admins can add users."}, status=status.HTTP_403_FORBIDDEN)

#     user_type = request.data.get("user_type")
#     if user_type not in ["manager", "employee"]:
#         return Response({"error": "Invalid user_type. Choose 'manager' or 'employee'."}, status=status.HTTP_400_BAD_REQUEST)

#     username = request.data.get("username")
#     email = request.data.get("email")
#     password = request.data.get("password")

#     if not all([username, email, password]):
#         return Response({"error": "Username, email, and password are required."}, status=status.HTTP_400_BAD_REQUEST)

#     if User.objects.filter(username=username).exists():
#         return Response({"error": "Username already exists."}, status=status.HTTP_400_BAD_REQUEST)

#     if User.objects.filter(email=email).exists():
#         return Response({"error": "Email already exists."}, status=status.HTTP_400_BAD_REQUEST)

#     first_name = request.data.get("first_name")
#     last_name = request.data.get("last_name")
#     gender = request.data.get("gender", "Not Specified")
#     designation = request.data.get("designation", "HR")
#     status_choice = request.data.get("status", "active")

#     if not all([first_name, last_name, designation]):
#         return Response({"error": "First name, last name, and designation are required."}, status=status.HTTP_400_BAD_REQUEST)

#     user = User.objects.create_user(username=username, email=email, password=password)

#     user_profile = UserProfile.objects.create(user=user, role=user_type, status=status_choice)

#     if user_type == "manager":
#         manager = Manager.objects.create(
#             user_profile=user_profile,
#             first_name=first_name,
#             last_name=last_name,
#             gender=gender,
#             email=email,
#             status=status_choice,
#             designation=designation
#         )
#         return Response({"message": "Manager created successfully.", "manager": ManagerSerializer(manager).data},
#                         status=status.HTTP_201_CREATED)

#     if user_type == "employee":
#         manager_id = request.data.get("manager")
#         manager = None
#         if manager_id:
#             try:
#                 manager = Manager.objects.get(id=manager_id)
#             except Manager.DoesNotExist:
#                 return Response({"error": "Manager not found."}, status=status.HTTP_400_BAD_REQUEST)

#         employee = Employee.objects.create(
#             user_profile=user_profile,
#             first_name=first_name,
#             last_name=last_name,
#             gender=gender,
#             email=email,
#             status=status_choice,
#             designation=designation,
#             manager=manager
#         )
#         return Response({"message": "Employee created successfully.", "employee": EmployeeSerializer(employee).data},
#                         status=status.HTTP_201_CREATED)


# @api_view(['DELETE'])
# @authentication_classes([TokenAuthentication])
# @permission_classes([IsAuthenticated])
# def delete_user(request, email):
#     """
#     Delete a user (Only Admin can delete Managers or Employees).
#     """
#     if not hasattr(request.user, 'admin_profile'):
#         return Response({"error": "Only admins can delete users."}, status=status.HTTP_403_FORBIDDEN)

#     try:
#         user = User.objects.get(email=email)
#     except User.DoesNotExist:
#         return Response({"error": "User not found."}, status=status.HTTP_404_NOT_FOUND)

#     if hasattr(user, 'employee_profile'):
#         user.employee_profile.delete()
#         user.delete()
#         return Response({"message": "Employee deleted successfully."}, status=status.HTTP_200_OK)

#     elif hasattr(user, 'manager_profile'):
#         if Employee.objects.filter(manager=user.manager_profile).exists():
#             return Response({"error": "Cannot delete manager with assigned employees."}, status=status.HTTP_400_BAD_REQUEST)

#         user.manager_profile.delete()
#         user.delete()
#         return Response({"message": "Manager deleted successfully."}, status=status.HTTP_200_OK)

#     return Response({"error": "User is neither an Employee nor a Manager."}, status=status.HTTP_400_BAD_REQUEST).



# from django.contrib.auth.models import User
# from rest_framework import serializers
# from .models import Profile, AdminUser, ManagerProfile, EmployeeProfile, TravelApplication

# # ========================== User & Profile Serializers ==========================

# class ProfileInfoSerializer(serializers.ModelSerializer):
#     """Handles serialization of user profile details along with user fields"""
#     username = serializers.SerializerMethodField()
#     email = serializers.SerializerMethodField()

#     class Meta:
#         model = Profile
#         fields = ['id', 'username', 'email', 'role', 'status']

#     def get_username(self, obj):
#         return obj.user.username

#     def get_email(self, obj):
#         return obj.user.email


# class UserRegistrationSerializer(serializers.ModelSerializer):
#     """Handles creation of user with hashed password and role assignment"""
#     password = serializers.CharField(write_only=True)
#     role = serializers.ChoiceField(choices=Profile.ROLE_CHOICES)

#     class Meta:
#         model = User
#         fields = ['id', 'username', 'email', 'password', 'role']

#     def create(self, validated_data):
#         role = validated_data.pop('role')
#         user = User.objects.create_user(
#             username=validated_data.get('username'),
#             email=validated_data.get('email'),
#             password=validated_data.get('password')
#         )
#         Profile.objects.create(user=user, role=role)
#         return user


# # ========================== Admin Serializers ==========================

# class AdminDetailSerializer(serializers.ModelSerializer):
#     """Serializer for admin data representation"""
#     user_info = ProfileInfoSerializer(source='user', read_only=True)

#     class Meta:
#         model = AdminUser
#         fields = ['id', 'user_info', 'username', 'email']


# # ========================== Manager Serializers ==========================

# class ManagerDetailSerializer(serializers.ModelSerializer):
#     """Serializer for manager data"""
#     profile = ProfileInfoSerializer(source='profile', read_only=True)

#     class Meta:
#         model = ManagerProfile
#         fields = ['id', 'profile', 'first_name', 'last_name', 'email', 'designation', 'status']


# # ========================== Employee Serializers ==========================

# class EmployeeDetailSerializer(serializers.ModelSerializer):
#     """Serializer for employee data"""
#     profile = ProfileInfoSerializer(source='profile', read_only=True)
#     reporting_manager = serializers.PrimaryKeyRelatedField(
#         queryset=ManagerProfile.objects.all(), allow_null=True, source='manager'
#     )

#     class Meta:
#         model = EmployeeProfile
#         fields = ['id', 'profile', 'first_name', 'last_name', 'email', 'designation', 'status', 'reporting_manager']


# # ========================== Travel Request Serializers ==========================

# class EmployeeTravelRequestViewSerializer(serializers.ModelSerializer):
#     """Used by employee to view own travel requests"""
#     approved_by = serializers.CharField(source='manager.first_name', read_only=True)

#     class Meta:
#         model = TravelApplication
#         fields = ['id', 'approved_by', 'from_location', 'to_location', 'start_date', 'end_date', 'status']


# class ManagerTravelApprovalSerializer(serializers.ModelSerializer):
#     """Used by manager to manage employee requests"""
#     applicant = serializers.CharField(source='employee.first_name', read_only=True)

#     class Meta:
#         model = TravelApplication
#         fields = ['id', 'applicant', 'status']


# class AdminTravelOverviewSerializer(serializers.ModelSerializer):
#     """Used by admin for full view of travel requests"""
#     employee_name = serializers.CharField(source='employee.first_name', read_only=True)
#     manager_name = serializers.CharField(source='manager.first_name', read_only=True)

#     class Meta:
#         model = TravelApplication
#         fields = ['id', 'employee_name', 'manager_name', 'from_location', 'to_location',
#                 'start_date', 'end_date', 'status', 'is_closed']
        
# from django.contrib import admin
# from django.urls import path
# from rest_framework.authtoken.views import obtain_auth_token
# from . import views

# urlpatterns = [

#     # =================== AUTHENTICATION ===================
#     path('initial_register_admin/', views.create_initial_admin, name='initial-register-admin'),
#     path('admin_login/', views.admin_login, name='admin-login'),
#     path('userlogin/', views.user_login, name='user-login'),
#     path('logout/', views.user_logout, name='user-logout'),

#     # =================== USER MANAGEMENT ===================
#     path('add_user/', views.add_user, name='add-user'),
#     path('delete_user/<str:email>/', views.delete_user, name='delete-user'),
#     path('admin/update-user/<int:user_id>/', views.update_user, name='update-user'),

#     # =================== EMPLOYEE APIs ===================
#     path('employee/dashboard/', views.employee_view_dashboard, name='employee-dashboard'),
#     path('employee/view-request/<int:request_id>/', views.employee_view_request, name='employee-view-request'),
#     path('employee/edit-request/<int:request_id>/', views.employee_edit_request, name='employee-edit-request'),
#     path('employee/cancel-request/<int:request_id>/', views.employee_cancel_request, name='employee-cancel-request'),
#     path('employee/submit-request/', views.employee_submit_request, name='employee-submit-request'),
#     path('employee/resubmit-request/<int:request_id>/', views.employee_resubmit_request, name='employee-resubmit-request'),

#     # =================== MANAGER APIs ===================
#     path('manager/view-requests/', views.manager_view_requests, name='manager-view-requests'),
#     # path('manager/process-request/<int:request_id>/', views.manager_process_request, name='manager-process-request'),

#     # =================== ADMIN APIs ===================
#     path('admin/travel-requests/', views.get_travel_requests, name='admin-travel-requests'),
#     path('admin/view-request/<int:request_id>/', views.get_travel_requests, name='admin-view-request'),
#     path('admin/update-request/<int:request_id>/', views.update_travel_request_status, name='admin-update-request'),
#     path('admin/request-info/<int:request_id>/', views.request_additional_info, name='admin-request-info'),
#     path('admin/process-close-request/<int:request_id>/', views.process_and_close_travel_request, name='admin-process-close-request'),

#     # =================== DATA LIST APIs ===================
#     path('api/employees/', views.get_all_employees, name='all-employees'),
#     path('admin/managers/', views.get_all_managers, name='all-managers'),

# ]