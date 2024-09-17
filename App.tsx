import React, { useState, useEffect } from 'react';
import 'react-native-url-polyfill/auto';
import { View, Button, Image, Text, StyleSheet, Alert, TextInput, ActivityIndicator } from 'react-native';
import { launchImageLibrary, ImageLibraryOptions, Asset } from 'react-native-image-picker';
import axios from 'axios';
import { CognitoIdentityClient } from "@aws-sdk/client-cognito-identity";
import { fromCognitoIdentityPool } from "@aws-sdk/credential-provider-cognito-identity";
import { CognitoUserPool, CognitoUser, AuthenticationDetails, CognitoUserSession } from 'amazon-cognito-identity-js';
import 'react-native-get-random-values';

const API_URL = 'https://sflkpf7ivf.execute-api.us-east-1.amazonaws.com/testing';
const IDENTITY_POOL_ID = 'us-east-1:fb9b4aa0-5b5d-40fc-97b0-7f51471252e6';
const USER_POOL_ID = 'us-east-1_QJJ74aa1b';
const CLIENT_ID = '6m04urkdq3o76k6gjah9jm99p9';
const REGION = 'us-east-1';

const userPool = new CognitoUserPool({
  UserPoolId: USER_POOL_ID,
  ClientId: CLIENT_ID,
});

const styles = StyleSheet.create({
  container: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
    padding: 20,
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
  buttonContainer: {
    marginTop: 10,
    width: '100%',
  },
});

const App = () => {
  const [selectedImage, setSelectedImage] = useState<string | null>(null);
  const [isUploading, setIsUploading] = useState(false);
  const [isProcessing, setIsProcessing] = useState(false);
  const [result, setResult] = useState<{ keypointImageUrl: string; predictedPosition: string } | null>(null);
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [changePasswordRequired, setChangePasswordRequired] = useState(false);
  const [cognitoUser, setCognitoUser] = useState<CognitoUser | null>(null);
  const [currentJobId, setCurrentJobId] = useState<string | null>(null);

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
      Alert.alert('Error', `Failed to sign in: ${error}`);
    }
  };

  const completeNewPasswordChallenge = () => {
    if (!cognitoUser) {
      Alert.alert('Error', 'No user found');
      return;
    }

    cognitoUser.completeNewPasswordChallenge(
      newPassword,
      {},
      {
        onSuccess: (session: CognitoUserSession) => {
          setIsAuthenticated(true);
          setChangePasswordRequired(false);
        },
        onFailure: (err: any) => {
          console.error('Error changing password:', err);
          Alert.alert('Error', 'Failed to change password');
        },
      }
    );
  };

  const signOut = async () => {
    if (cognitoUser) {
      cognitoUser.signOut();
      setCognitoUser(null);
      setIsAuthenticated(false);
      setResult(null);
      setCurrentJobId(null);
    }
  };

  const getCredentials = async (): Promise<{ identityId: string; token: string }> => {
    if (!cognitoUser) {
      throw new Error('User not authenticated');
    }

    return new Promise((resolve, reject) => {
      cognitoUser.getSession((err: Error | null, session: CognitoUserSession | null) => {
        if (err) {
          reject(err);
          return;
        }

        if (!session) {
          reject(new Error('No session found'));
          return;
        }

        const cognitoIdentityClient = new CognitoIdentityClient({
          credentials: fromCognitoIdentityPool({
            clientConfig: { region: REGION },
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
              token: session.getIdToken().getJwtToken()
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
      maxHeight: 2000,
      maxWidth: 2000,
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
    setCurrentJobId(null);

    try {
      const credentials = await getCredentials();
      const urlResponse = await axios.get(`${API_URL}/get_upload_url`, {
        params: { 
          file_type: 'image',
          user_id: credentials.identityId 
        },
        headers: {
          'Authorization': `Bearer ${credentials.token}`
        }
      });

      const { file_name, presigned_post, job_id } = urlResponse.data;

      const formData = new FormData();
      Object.entries(presigned_post.fields).forEach(([key, value]) => {
        formData.append(key, value as string);
      });

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

      setCurrentJobId(job_id);
      Alert.alert('Upload Successful', 'Image uploaded successfully. Processing will start automatically. You can check the status later.');
    } catch (error) {
      console.error('Error in uploadImage:', error);
      Alert.alert('Error', `Failed to upload image: ${(error as Error).message}`);
    } finally {
      setIsUploading(false);
    }
  };

  const checkProcessingStatus = async () => {
    if (!currentJobId) {
      Alert.alert('Error', 'No job in progress. Please upload an image first.');
      return;
    }

    setIsProcessing(true);
    try {
      const credentials = await getCredentials();
      const response = await axios.get(`${API_URL}/get_job_status/${currentJobId}`, {
        params: { user_id: credentials.identityId },
        headers: {
          'Authorization': `Bearer ${credentials.token}`
        }
      });

      const { status, s3_path, position } = response.data;

      if (status === 'COMPLETED') {
        setResult({
          keypointImageUrl: s3_path,
          predictedPosition: position,
        });
        Alert.alert('Processing Complete', `Your image has been processed. The detected position is: ${position}`);
      } else if (status === 'PROCESSING') {
        Alert.alert('In Progress', 'Your image is still being processed. Please check again later.');
      } else if (status === 'FAILED') {
        Alert.alert('Error', 'Image processing failed. Please try uploading again.');
      } else {
        Alert.alert('Unknown Status', `Current status: ${status}. Please try again later.`);
      }
    } catch (error) {
      console.error('Error checking processing status:', error);
      Alert.alert('Error', 'Failed to check processing status. Please try again.');
    } finally {
      setIsProcessing(false);
    }
  };

  if (!isAuthenticated) {
    if (changePasswordRequired) {
      return (
        <View style={styles.container}>
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
      <View style={styles.buttonContainer}>
        <Button title="Pick an image" onPress={pickImage} disabled={isUploading || isProcessing} />
      </View>
      <View style={styles.buttonContainer}>
        <Button title="Sign Out" onPress={signOut} />
      </View>
      {isUploading && <ActivityIndicator size="large" color="#0000ff" />}
      {currentJobId && (
        <View style={styles.buttonContainer}>
          <Button title="Check Processing Status" onPress={checkProcessingStatus} disabled={isProcessing} />
        </View>
      )}
      {isProcessing && <ActivityIndicator size="large" color="#0000ff" />}
      {selectedImage && (
        <Image source={{ uri: selectedImage }} style={styles.image} />
      )}
      {result && (
        <View>
          <Text style={styles.result}>Predicted Position: {result.predictedPosition}</Text>
          <Image source={{ uri: result.keypointImageUrl }} style={styles.image} />
        </View>
      )}
    </View>
  );
};

export default App;