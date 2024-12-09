<template>
  <div>
    <UCard class="w-full max-w-sm bg-white/75 backdrop-blur dark:bg-white/5">
      <Icon icon="AUC" class="size-auto" />

      <!-- Directly render the form for OTP verification -->
      <UAuthForm
        :fields="fields"
        :validate="validate"
        title="Verify Your Email"
        align="top"
        :ui="{ base: 'text-center', footer: 'text-center' }"
        :submit-button="{
          label: 'Verify',
          trailingIcon: 'i-heroicons-arrow-right-20-solid'
        }"
        :loading="loading"
        class="mt-5"
        @submit="onSubmit" <!-- The function to handle form submission -->
      >
        <template v-if="errorMessage" #validation>
          <UAlert
            color="red"
            icon="i-heroicons-information-circle-20-solid"
            :title="errorMessage"
          />
        </template>

        <template #footer>
          Already verified your email?
          <NuxtLink
            to="/loginpagetocyberrange"
            class="text-primary font-medium"
          >
            Go to Login Page
          </NuxtLink>
        </template>
      </UAuthForm>
    </UCard>
  </div>
</template>

<script setup>
import { ref } from 'vue';

const fields = [
  { label: 'OTP', name: 'otp', type: 'text', placeholder: 'Enter OTP', required: true },
  // You can add more fields if necessary
];

const errorMessage = ref('');
const loading = ref(false);

const validate = (values) => {
  // Add your form validation logic here
  if (!values.otp) {
    errorMessage.value = 'OTP is required';
    return false;
  }
  return true;
};

const onSubmit = async (values) => {
  // Handle the OTP verification process here
  loading.value = true;
  
  try {
    // Simulate sending OTP and verifying it (call your backend API here)
    const response = await verifyOTP(values.otp); // Define the verifyOTP function to check the OTP
    if (response.success) {
      // If OTP is correct, handle successful verification
      errorMessage.value = '';
      // Redirect to dashboard or next step
      navigateTo('/dashboard');
    } else {
      errorMessage.value = 'Invalid OTP. Please try again.';
    }
  } catch (error) {
    errorMessage.value = 'An error occurred. Please try again later.';
  } finally {
    loading.value = false;
  }
};

async function verifyOTP(otp) {
  // Simulate checking OTP from the backend (replace with real API call)
  if (otp === '123456') { // Example condition for successful OTP
    return { success: true };
  }
  return { success: false };
}
</script>
