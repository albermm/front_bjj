import React, { useState, useEffect } from 'react';
import 'react-native-url-polyfill/auto';
import { View, Button, Image, Text, StyleSheet, Alert, TextInput, ScrollView } from 'react-native';
import { launchImageLibrary, ImageLibraryOptions, Asset } from 'react-native-image-picker';
import Video from 'react-native-video';
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
  scrollView: {
    flex: 1,
    width: '100%',
  },
  media: {
    width: 300,
    height: 300,
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
  const [selectedMedia, setSelectedMedia] = useState<string | null>(null);
  const [isUploading, setIsUploading] = useState(false);
  const [result, setResult] = useState<{ mediaUrl: string; positionName: string; mediaType: 'image' | 'video' } | null>(null);
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

  const pickMedia = async () => {
    const options: ImageLibraryOptions = {
      mediaType: 'mixed',
      includeBase64: false,
    };

    try {
      const response = await launchImageLibrary(options);
      if (response.assets && response.assets.length > 0) {
        const asset = response.assets[0];
        if (asset.uri) {
          setSelectedMedia(asset.uri);
          await uploadMedia(asset);
        }
      }
    } catch (error) {
      console.error('Error picking media:', error);
      Alert.alert('Error', 'Failed to pick media');
    }
  };

  const uploadMedia = async (asset: Asset) => {
    if (!asset.uri) return;
    setIsUploading(true);
    setResult(null);
    setCurrentJobId(null);

    try {
      const credentials = await getCredentials();
      console.log('Obtained credentials:', credentials.identityId);
      const mediaType = asset.type?.startsWith('video') ? 'video' : 'image';
      console.log('Requesting upload URL for media type:', mediaType);

      const urlResponse = await axios.get(`${API_URL}/get_upload_url`, {
        params: { 
          user_id: credentials.identityId, 
          file_type: mediaType 
        },
        headers: {
          'Authorization': `Bearer ${credentials.token}`
        }
      });

      console.log('Received upload URL response:', urlResponse.data);

      const { file_name, presigned_post, job_id } = urlResponse.data;

      // Use the file_name as provided by the server
      const actualFileName = file_name;

      // Ensure the file is uploaded directly to the 'inputs' folder
      //const actualFileName = `inputs/${file_name.split('/').pop()}`;

      const formData = new FormData();
      Object.entries(presigned_post.fields).forEach(([key, value]) => {
        formData.append(key, value as string);
      });

      formData.append('file', {
        uri: asset.uri,
        type: asset.type || 'image/jpeg',
        name: actualFileName,
      } as any);

      console.log(`Uploading file: ${actualFileName}`);

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

      console.log(`File uploaded successfully. File name: ${actualFileName}, Job ID: ${job_id}`);

      setCurrentJobId(job_id);
      if (mediaType === 'video') {
        Alert.alert('Success', 'Video uploaded successfully. Processing may take longer for videos.');
      } else {
        Alert.alert('Success', 'Image uploaded successfully. You can now check the processing status.');
      }
    } catch (error) {
      console.error('Error in uploadMedia:', error);
      if (axios.isAxiosError(error)) {
        console.error('Axios error details:', error.response?.data);
        console.error('Axios error status:', error.response?.status);
        console.error('Axios error headers:', error.response?.headers);
      }
      Alert.alert('Error', `Failed to upload media: ${(error as Error).message}`);
    } finally {
      setIsUploading(false);
    }
  };

  const checkProcessingStatus = async () => {
    if (!currentJobId) {
      Alert.alert('Error', 'No job in progress. Please upload an image or video first.');
      return;
    }

    try {
      const credentials = await getCredentials();
      const response = await axios.get(`${API_URL}/get_job_status/${currentJobId}`, {
        params: { user_id: credentials.identityId },  // Add this line
        headers: {
          'Authorization': `Bearer ${credentials.token}`
        }
      });

      const { status, image_url, video_url, position, file_type } = response.data;

      if (status === 'COMPLETED') {
        setResult({
          mediaUrl: file_type === 'image' ? image_url : video_url,
          positionName: position,
          mediaType: file_type as 'image' | 'video'
        });
        Alert.alert('Processing Complete', `Your ${file_type} has been processed. The detected position is: ${position}`);
      } else if (status === 'PROCESSING') {
        Alert.alert('In Progress', 'Your media is still being processed. Please check again later.');
      } else if (status === 'FAILED') {
        Alert.alert('Error', 'Media processing failed. Please try uploading again.');
      } else {
        Alert.alert('Unknown Status', `Current status: ${status}. Please try again later.`);
      }
    } catch (error) {
      console.error('Error checking processing status:', error);
      Alert.alert('Error', 'Failed to check processing status. Please try again.');
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
    <ScrollView contentContainerStyle={styles.container}>
      <Button title="Pick an image or video" onPress={pickMedia} />
      <Button title="Sign Out" onPress={signOut} />
      {isUploading && <Text>Uploading...</Text>}
      {currentJobId && <Button title="Check Processing Status" onPress={checkProcessingStatus} />}
      {selectedMedia && (
        <Image source={{ uri: selectedMedia }} style={styles.media} />
      )}
      {result && (
        <View>
          <Text style={styles.result}>Predicted Position: {result.positionName}</Text>
          {result.mediaType === 'image' ? (
            <Image source={{ uri: result.mediaUrl }} style={styles.media} />
          ) : (
            <Video source={{ uri: result.mediaUrl }} style={styles.media} controls />
          )}
        </View>
      )}
    </ScrollView>
  );
};

export default App;