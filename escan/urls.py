from django.urls import path, include
from escan import views
from django.conf import settings
from django.conf.urls.static import static


urlpatterns = [
    path('', views.landing_page, name='landing_page'),
    path('accounts/', include('allauth.urls')),
    path("login/", views.login_view, name="login"),
    path("signup_view/", views.signup_view, name="signup_view"), 
    path("fnavbase/", views.fnavbase, name="fnavbase"),
    path("a_scan_nav/", views.a_scan_nav, name="a_scan_nav"),
    
    # Admin Scan
    path('admin/dashboard/', views.admin_dashboard, name='admin_dashboard'),
    path("a_scan/", views.a_scan, name="a_scan"),
    path('a_banana_disease/', views.a_banana_disease, name='a_banana_disease'),
    path('a_predict-from-camera/', views.a_predict_from_camera, name='a_predict_from_camera'),
    path('a_banana_variety/', views.a_banana_variety, name='a_banana_variety'),
    path('a_disease_scan-history/', views.a_disease_scan_history, name='a_disease_scan_history'),
    path('a_variety_scan-history/', views.a_variety_scan_history, name='a_variety_scan_history'),
    path('a_scan-result/<int:record_id>/', views.a_view_scan_result, name='a_view_scan_result'),
    path('a_predict-variety-camera/', views.a_predict_variety_from_camera, name='a_predict_variety_from_camera'),
    # for admin
    path("admin_dashboard/", views.admin_dashboard, name="admin_dashboard"),
    # path("update_profile/", views.update_profile, name="update_profile"),
    
    # User list Management
    path("user_table/", views.user_table, name="user_table"),
    path("add_user/", views.add_user, name="add_user"),
    path("edit_user/<int:user_id>/", views.edit_user, name="edit_user"),
    path("delete_user/<int:user_id>/", views.delete_user, name="delete_user"),
    path("undo_last_action_user/", views.undo_last_action_user, name="undo_last_action_user"),
    path('search_users/', views.search_users, name='search_users'),
    path('user_print/', views.user_print, name='user_print'),


    #Admmin Side Settings..
    path("a_setting/", views.a_setting, name="a_setting"),
    # admin Store
    path('create_store/', views.create_store, name='create_store'),
    # path('store/create/', views.create_store, name='create_store'),
    path('store/update/', views.update_store, name='update_store'),
    path('update-store/', views.update_store, name='update_store'),

     # Admin Categories
    path('category_list/', views.category_list, name='category_list'),
    path('add-category/', views.add_category, name='add_category'),
    path('edit-category/<int:category_id>/', views.edit_category, name='edit_category'),
    path('delete-category/<int:category_id>/', views.delete_category, name='delete_category'),
    path('categories/', views.category_list, name='category_list'),

    # Admin Side Products
    path('products/', views.product_list, name='product_list'),
    path('add_product/', views.add_product, name='add_product'),
    path('edit_product/<int:product_id>/', views.edit_product, name='edit_product'),
    path('delete_product/<int:product_id>/', views.delete_product, name='delete_product'),
    path('undo/', views.undo_last_action, name='undo_last_action'),
    path('search_products/', views.search_products, name='search_products'),
    path('product_print/', views.product_print, name='product_print'),
    

    # Admin Side Oders
    path('orders_part/', views.orders_part, name='orders_part'),
    path('orders/update/<int:order_id>/', views.update_order_status, name='update_order_status'),
    path('add_review/', views.add_review, name='add_review'),
    path('orders/', views.orders_part, name='orders_part'),
    path("orders/set-schedule/", views.set_order_schedule, name="set_order_schedule"),
    path('set-delivery-schedule/', views.set_delivery_schedule, name='set_delivery_schedule'),
    path('update-order-status/<int:order_id>/', views.update_order_status, name='update_order_status'),
 
    # Admin marketplace
    path("a_market_place/", views.a_market_place, name="a_market_place"),
    path('carts/', views.carts, name = 'carts'), 
    path('add_to_carts/<int:product_id>/', views.add_to_carts, name='add_to_carts'),
    path('update/<int:item_id>/', views.update_cart_items, name='update_cart_items'),
    path('remove/<int:item_id>/', views.remove_from_carts, name='remove_from_carts'),
    path('checkout-item/<int:item_id>/', views.direct_item_checkout, name='direct_item_checkout'),
    path('checkouts/', views.checkout_view, name='checkouts'),
    path('order-confirmation/<int:order_id>/', views.order_confirmation_view, name='order_confirmation'),
    path('order-confirmation/', views.order_confirmation_view, name='order_confirmation'),
    path('a_payment/gcash/success/', views.a_paymongo_success, name='a_paymongo_success'),

    path('checkout/direct/', views.handle_direct_checkout, name='direct_checkout'),
    path('a_payment/gcash/failed/', views.a_paymongo_failed, name='a_paymongo_failed'),
    path('a_set-default-address/<int:address_id>/', views.a_set_default_address, name='a_set_default_address'),
    path('a_payment/gcash/', views.a_create_gcash_payment, name='a_gcash_payment'),
    path('a_payment/success/', views.a_payment_success, name='a_payment_success'),
    path('a_payment/failed/', views.a_payment_failed, name='a_payment_failed'),
    

    # Market Entity
    path("m_setting/", views.m_setting, name="m_setting"),
    path("market_landing/", views.market_landing, name="market_landing"),
    path('u_update-order/', views.u_update_order, name='u_update_order'),
    path('update-order-status/<int:order_id>/', views.u_update_order_status, name='u_update_order_status'),

    path('customers/<int:customer_id>/', views.customer_detail, name='customer_detail'),
    # marketplace(store)
    path('user/orders/', views.my_orders_part, name='my_orders_part'),
    path("market_place/", views.market_place, name="market_place"),
    path("marketplace_dashboard/", views.marketplace_dashboard, name="marketplace_dashboard"),
    path('u_carts/', views.u_carts, name = 'u_carts'), 
    path('u_add_to_carts/<int:product_id>/', views.u_add_to_carts, name='u_add_to_carts'),
    path('u_update/<int:item_id>/', views.u_update_cart_items, name='u_update_cart_items'),
    path('u_remove/<int:item_id>/', views.u_remove_from_carts, name='u_remove_from_carts'),
    path('u_checkout/direct/', views.handle_direct_checkouts, name='u_direct_checkout'),
    path('direct-checkout/<int:item_id>/', views.u_direct_item_checkouts, name='u_direct_item_checkouts'),
    path('store/<int:store_id>/shipping-fees/', views.u_manage_shipping_fees, name='u_manage_shipping_fees'),
    path('u_checkouts/', views.u_checkout_view, name='u_checkouts'),
    path('u_order-confirmation/<int:order_id>/', views.u_order_confirmation_view, name='u_order_confirmation'),
    path('u_order-confirmation/', views.u_order_confirmation_view, name='u_order_confirmation'),
    path('set-default-address/<int:address_id>/', views.set_default_address, name='set_default_address'),
    path('update-address/<int:address_id>/', views.update_shipping_address, name='update_shipping_address'),

    path('payment/gcash/', views.create_gcash_payment, name='gcash_payment'),
    path('payment/success/', views.payment_success, name='payment_success'),
    path('payment/failed/', views.payment_failed, name='payment_failed'),

    path('payment/gcash/success/', views.paymongo_success, name='paymongo_success'),
    path('payment/gcash/failed/', views.paymongo_failed, name='paymongo_failed'),
    # path('paypal/execute/', views.paypal_execute, name='paypal_execute'),
    # path('paypal/cancel/', views.paypal_cancel, name='paypal_cancel'),
    path('checkout/direct/', views.handle_direct_checkouts, name='u_direct_checkout'),

    path('validations/', views.validation_list, name='validation_list'),
    path('validations/<int:pk>/approve/', views.approve_validation, name='approve_validation'),
    path("validations/<int:pk>/", views.validation_detail, name="validation_detail"),
    path('validations/<int:pk>/update/', views.update_validation_status, name='update_validation_status'),
    path('validations/<int:pk>/reject/', views.reject_validation, name='reject_validation'),

    
    # Market Entity my store  m_setting
    path("my_store_dashboard/", views.my_store_dashboard, name="my_store_dashboard"),
    path('my_store_orders_part/', views.my_store_orders_part, name='my_store_orders_part'),
    path("my_store/", views.my_store, name="my_store"),
    path('apply-seller/', views.apply_seller, name='apply_seller'),
    path('u_create-store/', views.u_create_store, name='u_create_store'),
    path('u_update-store/', views.u_update_store, name='u_update_store'),
    path('u_categories/', views.u_category_list, name='u_category_list'),
    path('my_store/', views.my_store, name='my_store'),
    path('u_create_store/', views.u_create_store, name='u_create_store'),
    path('u_update_store/', views.u_update_store, name='u_update_store'),
    path('u_add_product/', views.u_add_product, name='u_add_product'),
    path('u_edit_product/<int:product_id>/', views.u_edit_product, name='u_edit_product'),
    path('u_delete_product/<int:product_id>/', views.u_delete_product, name='u_delete_product'),
    path('u_undo_last_action/', views.u_undo_last_action, name='u_undo_last_action'),
    path('u_search_products/', views.u_search_products, name='u_search_products'),

    # User Side Manage Store
    path('u_products/', views.u_product_list, name='u_product_list'),
    path('u_add_product/', views.u_add_product, name='u_add_product'),
    path('u_edit_product/<int:product_id>/', views.u_edit_product, name='u_edit_product'),
    path('u_delete_product/<int:product_id>/', views.u_delete_product, name='u_delete_product'),
    path('u_undo/', views.u_undo_last_action, name='u_undo_last_action'),
    path('u_search_products/', views.u_search_products, name='u_search_products'),
    path('u_product_print/', views.u_product_print, name='u_product_print'),
    # Market Entity My Store Orders
    path('user/orders/', views.my_orders_part, name='my_orders_part'),
    path('user/orders/add-review/', views.u_add_review, name='u_add_review'),
    path('user/orders/update-status/<int:order_id>/', views.u_update_order_status, name='u_update_order_status'),
    
    
    #User Side Categories
    path('u_add-category/', views.u_add_category, name='u_add_category'),
    path('u_edit-category/<int:category_id>/', views.u_edit_category, name='u_edit_category'),
    path('u_delete-category/<int:category_id>/', views.u_delete_category, name='u_delete_category'),
  
    

    # User side cart operations
    path('u_add_to_cart/<int:product_id>/', views.u_add_to_carts, name='u_add_to_cart'),
    path('u_update_cart_items/<int:item_id>/', views.u_update_cart_items, name='u_update_cart_items'),
    path('u_remove_from_cart/<int:item_id>/', views.u_remove_from_carts, name='u_remove_from_cart'),
    # Customers
    path("customer_table/", views.customer_table, name="customer_table"),
    path("customer_list/", views.u_customer_table, name="u_customer_list"),
    # Customer print view
    path('customer/<int:customer_id>/print/', views.customer_print, name='customer_print'),
    # Customer print preview
    path('customer/<int:customer_id>/print-preview/', views.customer_print_preview, name='customer_print_preview'),
    # Bulk customer printing
    path('customers/print-selected/', views.print_selected_customers, name='print_selected_customers'),
    


    # Farmer Side 
     path('farmer/dashboard/', views.farmer_dashboard, name='farmer_dashboard'),
     path("farmer_dashboard/", views.farmer_dashboard, name="farmer_dashboard"),
     path('api/farmer-dashboard-data/', views.farmer_dashboard_data, name='farmer_dashboard_data'),
     path('api/ get_weather_context/', views. get_weather_context, name=' get_weather_context'),
     path('api/export-dashboard/', views.export_dashboard_data, name='export_dashboard_data'),
     # Farmer Scan
    path('banana_disease/', views.banana_disease, name='banana_disease'),
    path('banana_variety/', views.banana_variety, name='banana_variety'),
    path('predict-from-camera/', views.predict_from_camera, name='predict_from_camera'),
    path('predict-variety-camera/', views.predict_variety_from_camera, name='predict_variety_from_camera'),
    path('disease_scan-history/', views.disease_scan_history, name='disease_scan_history'),
    path('variety_scan-history/', views.variety_scan_history, name='variety_scan_history'),
    path('scan-result/<int:record_id>/', views.view_scan_result, name='view_scan_result'),
    
    
    # Farmer Side Scan
     path("scan/", views.scan, name="scan"),
    # Farmer Side Settings
    path("f_setting/", views.f_setting, name="f_setting"),

    #Admin Side Graphs
     path('user_graph/', views.user_graph_view, name='user_graph'),

    #  User Parts
      # path("update_userprofile/", views.update_userprofile, name="update_userprofile"),

  # AJAX endpoints for settings
    path('ajax/update-profile/', views.update_profile_ajax, name='update_profile_ajax'),
    path('ajax/update-store/', views.update_store_ajax, name='update_store_ajax'),
    path('ajax/update-shipping-address/', views.update_shipping_address_ajax, name='update_shipping_address_ajax'),
    path('ajax/get-user-data/', views.get_user_data, name='get_user_data'),


     # Google Authentication URLs
    # path("shop_signup/google/", views.google_signup, name="google_signup"),
    # path("auth/callback/", views.auth_callback, name="auth_callback"),

    # forgot password
    path('forgot-password/', views.ForgotPassword, name='forgot-password'),
    path('password-reset-sent/<str:reset_id>/', views.PasswordResetSent, name='password-reset-sent'),
    path('reset-password/<str:reset_id>/', views.ResetPassword, name='reset-password'),

    #messages/inbox
    # path('messages/', views.inbox, name='inbox'),
    path('compose/', views.compose_message, name='compose_message'),
    path('thread/<int:thread_id>/', views.thread_view, name='thread'),
    path('messages/send/', views.send_message, name='send_message'),
    path('unread-message-count/', views.unread_message_count, name='unread_message_count'),
    path('mark-messages-as-read/', views.mark_messages_as_read, name='mark_messages_as_read'),
    path('mark-single-message-as-read/', views.mark_single_message_as_read, name='mark_single_message_as_read'),
    path('latest_message/', views.latest_message_for_thread, name='latest_message_for_thread'),
    path('thread/', views.thread_placeholder, name='thread_placeholder'),
    # path('mark-as-read/<int:message_id>/', views.mark_as_read, name='mark_as_read'),

    #Logout
     path('logout/', views.user_logout, name='logout'),
     path('i18n/', include('django.conf.urls.i18n')),
]+ static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)


# Not use
# path("user_base/", views.user_base, name="user_base"),