import { useEffect } from "react";
import { MainContainer } from "./components/MainContainer";
import { invoke } from '@tauri-apps/api/core';
import "./styles/main.css";

function App() {
  useEffect(() => {
    // Initialize app handle for event emission
    const initializeApp = async () => {
      try {
        await invoke('initialize_callbacks');
        console.log('App initialized successfully');
      } catch (error) {
        console.error('Failed to initialize app:', error);
      }
    };

    initializeApp();
  }, []);

  return (
    <MainContainer />
  );
}

export default App;