import React, { useState, useEffect } from 'react';
import 'react-native-url-polyfill/auto';
import { View, Button, Image, Text, StyleSheet, Alert, TextInput, Platform } from 'react-native';
import { launchImageLibrary, ImageLibraryOptions, Asset } from 'react-native-image-picker';
import axios, { AxiosError } from 'axios';
import { CognitoIdentityClient, GetIdCommand } from "@aws-sdk/client-cognito-identity";
import { fromCognitoIdentityPool } from "@aws-sdk/credential-provider-cognito-identity";
import { CognitoUserPool, CognitoUser, AuthenticationDetails, CognitoUserSession } from 'amazon-cognito-identity-js';
import 'react-native-get-random-values';

const API_URL = 'https://sflkpf7ivf.execute-api.us-east-1.amazonaws.com/testing';
const IDENTITY_POOL_ID = 'us-east-1:fb9b4aa0-5b5d-40fc-97b0-7f51471252e6';
const USER_POOL_ID = 'us-east-1_QJJ74aa1b';
const CLIENT_ID = '6m04urkdq3o76k6gjah9jm99p9'; 
const REGION = 'us-east-1';
const BUCKET_NAME = 'bjj-pics';

const userPool = new CognitoUserPool({
  UserPoolId: USER_POOL_ID,
  ClientId: CLIENT_ID,
});

const styles = StyleSheet.create({
  container: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
  },
  image: {
    width: 200,
    height: 200,
    marginTop: 20,
  },
  result: {
    marginTop: 20,
    fontSize: 16,
    fontWeight: 'bold',
  },
  input: {
    width: 200,
    height: 40,
    borderColor: 'gray',
    borderWidth: 1,
    marginBottom: 10,
    paddingLeft: 10,
  },
});

const App = () => {
  const [selectedImage, setSelectedImage] = useState<string | null>(null);
  const [isUploading, setIsUploading] = useState(false);
  const [result, setResult] = useState<{ keypointsImage: string; positionName: string } | null>(null);
  const [isProcessing, setIsProcessing] = useState(false);
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [changePasswordRequired, setChangePasswordRequired] = useState(false);
  const [cognitoUser, setCognitoUser] = useState<CognitoUser | null>(null);

  useEffect(() => {
    checkAuthState();
  }, []);

  const checkAuthState = async () => {
    try {
      const user = await new Promise<CognitoUser | null>((resolve, reject) => {
        const currentUser = userPool.getCurrentUser();
        if (currentUser) {
          currentUser.getSession((err: Error | null, session: CognitoUserSession | null) => {
            if (err) {
              reject(err);
            } else if (session && session.isValid()) {
              resolve(currentUser);
            } else {
              resolve(null);
            }
          });
        } else {
          resolve(null);
        }
      });

      if (user) {
        setCognitoUser(user);
        setIsAuthenticated(true);
      } else {
        setIsAuthenticated(false);
      }
    } catch (error) {
      console.error('Error checking auth state:', error);
      setIsAuthenticated(false);
    }
  };

  const signIn = async () => {
    try {
      const authenticationDetails = new AuthenticationDetails({
        Username: username,
        Password: password,
      });

      const user = new CognitoUser({
        Username: username,
        Pool: userPool,
      });

      user.authenticateUser(authenticationDetails, {
        onSuccess: (session) => {
          setCognitoUser(user);
          setIsAuthenticated(true);
        },
        onFailure: (err) => {
          console.error('Error signing in:', err);
          Alert.alert('Error', 'Failed to sign in');
        },
        newPasswordRequired: (userAttributes, requiredAttributes) => {
          setCognitoUser(user);
          setChangePasswordRequired(true);
        },
      });
    } catch (error) {
        console.error('Error signing in:', error);
        if (error instanceof Error) {
          console.error('Error message:', error.message);
          console.error('Error stack:', error.stack);
        }
        Alert.alert('Error', `Failed to sign in: ${error}`);
      }
    };

  const completeNewPasswordChallenge = () => {
    if (!cognitoUser) {
      Alert.alert('Error', 'No user found');
      return;
    }

    cognitoUser.completeNewPasswordChallenge(newPassword, {}, {
      onSuccess: (session: CognitoUserSession) => {
        setIsAuthenticated(true);
        setChangePasswordRequired(false);
      },
      onFailure: (err: any) => {
        console.error('Error changing password:', err);
        Alert.alert('Error', 'Failed to change password');
      },
    });
  };

  const signOut = async () => {
    if (cognitoUser) {
      cognitoUser.signOut();
      setCognitoUser(null);
      setIsAuthenticated(false);
    }
  };

  const getCredentials = async (): Promise<{ identityId: string; token: string }> => {
    if (!cognitoUser) {
      console.error('No cognitoUser found');
      throw new Error('User not authenticated');
    }
  
    return new Promise((resolve, reject) => {
      cognitoUser.getSession((err: Error | null, session: CognitoUserSession | null) => {
        if (err) {
          console.error('Error getting session:', err);
          reject(err);
          return;
        }
        if (!session) {
          reject(new Error('No session found'));
          return;
        }
  
        console.log('Session obtained successfully');
        const cognitoIdentityClient = new CognitoIdentityClient({
          credentials: fromCognitoIdentityPool({
            clientConfig: { region: "us-east-1" },
            identityPoolId: IDENTITY_POOL_ID,
            logins: {
              [`cognito-idp.${REGION}.amazonaws.com/${USER_POOL_ID}`]: session.getIdToken().getJwtToken(),
            },
          }),
        });
  
        cognitoIdentityClient.config.credentials().then((credentials: any) => {
          if (typeof credentials.identityId === 'string') {
            resolve({
              identityId: credentials.identityId,
              token: session.getIdToken().getJwtToken() // Add this line
            });
          } else {
            reject(new Error('Invalid credentials format'));
          }
        }).catch(reject);
      });
    });
  };


  const pickImage = async () => {
    const options: ImageLibraryOptions = {
      mediaType: 'photo',
      includeBase64: false,
      maxHeight: 200,
      maxWidth: 200,
    };

    try {
      const response = await launchImageLibrary(options);
      if (response.assets && response.assets.length > 0) {
        const asset = response.assets[0];
        if (asset.uri) {
          setSelectedImage(asset.uri);
          await uploadImage(asset);
        }
      }
    } catch (error) {
      console.error('Error picking image:', error);
      Alert.alert('Error', 'Failed to pick image');
    }
  };


  const uploadImage = async (asset: Asset) => {
    if (!asset.uri) return;
    setIsUploading(true);
    setResult(null);
  
    try {
      console.log('Getting credentials...');
      const credentials = await getCredentials();
      console.log('Credentials obtained:', credentials.identityId);
  
      console.log('Making API call to:', `${API_URL}/get_upload_url`);
      console.log('With user_id:', credentials.identityId);
      const urlResponse = await axios.get(`${API_URL}/get_upload_url`, {
        params: { user_id: credentials.identityId },
      });
      console.log('API Response:', urlResponse.data);
  
      const { file_name, presigned_post, job_id } = urlResponse.data;
  
      if (!presigned_post || !presigned_post.url) {
        throw new Error('Presigned POST data not provided by the API');
      }
  
      const formData = new FormData();
      Object.entries(presigned_post.fields).forEach(([key, value]) => {
        formData.append(key, value as string);
      });
  
      // Append file to FormData
      formData.append('file', {
        uri: asset.uri,
        type: asset.type || 'image/jpeg', 
        name: file_name,
      } as any);
  
      const uploadResponse = await fetch(presigned_post.url, {
        method: 'POST',
        body: formData,
        headers: {
          'Content-Type': 'multipart/form-data',
        },
      });
  
      if (!uploadResponse.ok) {
        throw new Error(`Upload failed with status ${uploadResponse.status}`);
      }
  
      Alert.alert('Success', 'Image uploaded successfully');
      pollForResult(file_name, job_id);
    } catch (error: unknown) {
      console.error('Error in uploadImage:', error);
      if (axios.isAxiosError(error) && error.response) {
        console.error('Error response:', error.response.data);
        console.error('Error status:', error.response.status);
        console.error('Error headers:', error.response.headers);
      }
      Alert.alert('Error', `Failed to upload image: ${(error as Error).message}`);
    } finally {
      setIsUploading(false);
    }
  };

  const pollForResult = async (fileName: string, jobId: string) => {
    setIsProcessing(true);
    let retries = 0;
    const maxRetries = 60; // Increased for longer processes
    const initialRetryDelay = 5000; // 5 seconds
    const longRetryDelay = 30000; // 30 seconds
  
    const poll = async () => {
      try {
        const credentials = await getCredentials();
        console.log('Polling with credentials:', credentials.identityId);
        
        const response = await axios.get(`${API_URL}/get_job_status/${jobId}`, {
          headers: {
            'Authorization': `Bearer ${credentials.token}`
          }
        });
  
        const { status, image_url, keypoints_url, position, updatedAt } = response.data;
  
        console.log(`Job status: ${status}, Updated at: ${updatedAt}`);
  
        if (status === 'success') {
          setResult({
            keypointsImage: image_url,
            positionName: position,
          });
          setIsProcessing(false);
          Alert.alert('Processing Complete', `Your image has been processed. The detected position is: ${position}`);
        } else if (status === 'PROCESSING' || !status) {
          if (retries < maxRetries) {
            console.log(`Still processing, retrying in ${retries < 12 ? initialRetryDelay : longRetryDelay / 1000} seconds...`);
            retries++;
            setTimeout(poll, retries < 12 ? initialRetryDelay : longRetryDelay);
          } else {
            console.error('Max retries reached');
            Alert.alert('Error', 'Processing timed out');
            setIsProcessing(false);
          }
        } else {
          console.error('Unknown status:', status);
          Alert.alert('Error', 'An unexpected error occurred. Please try again.');
          setIsProcessing(false);
        }
      } catch (error) {
        console.error('Error polling for result:', error);
        if (axios.isAxiosError(error)) {
          console.error('Error response:', error.response?.data);
          console.error('Error status:', error.response?.status);
          console.error('Error headers:', error.response?.headers);
          
          if (error.response?.status === 404) {
            console.error('Job not found. It might not have been created yet.');
            if (retries < maxRetries) {
              console.log(`Job not found, retrying in ${initialRetryDelay / 1000} seconds...`);
              retries++;
              setTimeout(poll, initialRetryDelay);
              return;
            }
          }
          
          if (error.response?.status === 403) {
            console.error('Authentication error. Ensure your credentials are correct.');
            Alert.alert('Error', 'Authentication failed. Please sign in again.');
            setIsAuthenticated(false);
          } else {
            Alert.alert('Error', `Failed to get processing result: ${error.message}`);
          }
        } else {
          Alert.alert('Error', 'An unexpected error occurred');
        }
        setIsProcessing(false);
      }
    };
  
    poll();
  }


  if (!isAuthenticated) {
    if (changePasswordRequired) {
      return (
        <View style={styles.container}>
          <Text>You need to change your password</Text>
          <TextInput
            style={styles.input}
            placeholder="New Password"
            secureTextEntry
            value={newPassword}
            onChangeText={setNewPassword}
          />
          <Button title="Change Password" onPress={completeNewPasswordChallenge} />
        </View>
      );
    }

    return (
      <View style={styles.container}>
        <TextInput
          style={styles.input}
          placeholder="Username"
          value={username}
          onChangeText={setUsername}
        />
        <TextInput
          style={styles.input}
          placeholder="Password"
          secureTextEntry
          value={password}
          onChangeText={setPassword}
        />
        <Button title="Sign In" onPress={signIn} />
      </View>
    );
  }

  return (
    <View style={styles.container}>
      <Button title="Pick an image" onPress={pickImage} />
      <Button title="Sign Out" onPress={signOut} />
      {isUploading && <Text>Uploading...</Text>}
      {isProcessing && <Text>Processing...</Text>}
      {selectedImage && <Image source={{ uri: selectedImage }} style={styles.image} />}
      {result && (
        <View>
          <Image source={{ uri: result.keypointsImage }} style={styles.image} />
          <Text style={styles.result}>Predicted Position: {result.positionName}</Text>
        </View>
      )}
    </View>
  );
};

export default App;
